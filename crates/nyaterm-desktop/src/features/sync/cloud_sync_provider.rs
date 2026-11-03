use crate::http::cloud_sync::{
    NativeAliyunDriveRemote, NativeGoogleDriveRemote, NativeOneDriveRemote, NativeS3Remote,
    NativeSnippetHttpClient, NativeWebdavRemote,
};
use nyaterm_core::cloud_sync::control::CloudSyncOperationControl;
use nyaterm_core::cloud_sync::{self, CloudSyncRemote};
use nyaterm_core::{
    CloudSyncError, CloudSyncResult, CloudSyncSettings, CloudSyncState, GiteeSnippetHttpBackend,
    GithubGistHttpBackend, LocalCloudSyncOptions, RemoteSyncPointer, SnippetRemote,
};
use nyaterm_store::{StoreBlockingClient, StoreDomain};

macro_rules! with_provider_remote {
    ($store:expr, $settings:ident, $options:expr, $label:expr, $remote:ident, $caches:ident, $body:block) => {{
        let fresh = $store
            .request_fn(StoreDomain::CloudSync, |store| {
                store.load_cloud_sync_settings()
            })
            .map_err(|_| CloudSyncError::CredentialPersistence)?;
        let mut expected = $settings.clone();
        let mut pending = expected.clone();
        nyaterm_core::cloud_sync::credentials::rebase_rotated_tokens(
            &mut expected,
            &mut pending,
            &fresh,
        );
        if expected != fresh {
            return Err(CloudSyncError::CredentialsChanged);
        }
        let $settings = &fresh;
        let mut io_scope = super::io_runtime::IoScope::new($label);
        let io = super::io_runtime::CloudSyncIoRuntime::shared();
        let $caches = io.caches($store, $settings, $options)?;

        let token_store = $store.clone();
        let token_sink: crate::http::cloud_sync::CloudTokenSink =
            std::sync::Arc::new(move |update| {
                let result = token_store
                    .request_fn(StoreDomain::CloudSync, move |store| {
                        store.update_cloud_credentials(&update)
                    })
                    .map_err(|_| CloudSyncError::CredentialPersistence)?;
                match result {
                    nyaterm_core::cloud_sync::credentials::CredentialUpdateResult::Applied => {
                        Ok(())
                    }
                    nyaterm_core::cloud_sync::credentials::CredentialUpdateResult::Superseded => {
                        Err(CloudSyncError::CredentialsChanged)
                    }
                }
            });
        let result = (|| {
            let native: Box<dyn CloudSyncRemote> = match $settings.provider.as_str() {
                "webdav" => Box::new(NativeWebdavRemote::new(&$settings.webdav)?),
                "s3" => Box::new(NativeS3Remote::new_with_stats(
                    &$settings.s3,
                    io_scope.stats.clone(),
                )?),
                "google_drive" => Box::new(NativeGoogleDriveRemote::new_with_token_sink(
                    &$settings.google_drive,
                    token_sink.clone(),
                )?),
                "onedrive" => Box::new(NativeOneDriveRemote::new_with_token_sink(
                    &$settings.onedrive,
                    token_sink.clone(),
                )?),
                "aliyun_drive" => Box::new(NativeAliyunDriveRemote::new_with_token_sink(
                    &$settings.aliyun_drive,
                    token_sink.clone(),
                )?),
                "gitee_snippet" => Box::new(SnippetRemote::new(
                    "gitee_snippet",
                    GiteeSnippetHttpBackend::new(
                        &$settings.gitee_snippet,
                        NativeSnippetHttpClient::new()?,
                    )?,
                )),
                "github_gist" => Box::new(SnippetRemote::new(
                    "github_gist",
                    GithubGistHttpBackend::new(
                        &$settings.github_gist,
                        NativeSnippetHttpClient::new()?,
                    )?,
                )),
                provider => {
                    return Err(CloudSyncError::Remote(format!(
                        "native cloud provider '{provider}' is not wired yet"
                    )));
                }
            };
            let observed = super::io_runtime::ObservedRemote {
                inner: native.as_ref(),
                stats: io_scope.stats.clone(),
                heads_checked: std::cell::Cell::new(false),
            };
            let $remote = nyaterm_core::cloud_sync::metadata_cache::CachedMetadataRemote::new(
                &observed,
                &$caches.metadata,
                &$settings.remote_root,
            );
            let run = || $body;
            let result = run();
            if result.is_ok() && matches!($label, "push" | "pull" | "resolve" | "recover") {
                $caches
                    .pending_remote
                    .store(false, std::sync::atomic::Ordering::Release);
            }
            if (result.is_ok() || matches!(&result, Err(CloudSyncError::Conflict(_))))
                && observed.heads_checked.get()
                && !matches!($label, "cleanup" | "connection_test")
            {
                io.checked();
            }
            if result.is_err()
                && ($label != "check" || !matches!(&result, Err(CloudSyncError::Conflict(_))))
            {
                *$caches
                    .validation
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Default::default();
                $caches
                    .pending_remote
                    .store(true, std::sync::atomic::Ordering::Release);
            }
            result
        })();
        io_scope.finish(&result);
        result
    }};
}

pub(super) fn with_remote<T>(
    local_store: &StoreBlockingClient,
    settings: &CloudSyncSettings,
    options: &LocalCloudSyncOptions,
    label: &'static str,
    operation: impl FnOnce(
        &dyn CloudSyncRemote,
        &super::io_runtime::IoCaches,
    ) -> Result<T, CloudSyncError>,
) -> Result<T, CloudSyncError> {
    if settings.protocol_version != 3 && !label.starts_with("v4_") && label != "connection_test" {
        return Err(CloudSyncError::Remote(
            "Legacy sync writing is disabled for this protocol".into(),
        ));
    }
    if settings.provider == "local_directory" {
        let remote = nyaterm_core::LocalDirectoryRemote::new(options.remote_dir.clone());
        let caches = super::io_runtime::CloudSyncIoRuntime::shared().caches(
            local_store,
            settings,
            Some(options),
        )?;
        return operation(&remote, &caches);
    }
    with_provider_remote!(
        local_store,
        settings,
        Some(options),
        label,
        remote,
        caches,
        { operation(&remote, &caches) }
    )
}

pub(crate) fn check_provider_snapshot(
    local_store: &StoreBlockingClient,
    settings: &CloudSyncSettings,
    options: &LocalCloudSyncOptions,
    state: &CloudSyncState,
    control: &CloudSyncOperationControl,
) -> Result<cloud_sync::CloudSyncCheck, CloudSyncError> {
    control.checkpoint()?;
    with_remote(local_store, settings, options, "check", |remote, caches| {
        let mut cache = caches
            .validation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let result = cloud_sync::check_snapshot_with_remote_cached(
            &control.local_store(local_store),
            options,
            &control.remote(remote),
            state,
            settings.auto_pull_remote_changes,
            &mut cache,
        );
        use std::sync::atomic::Ordering;
        match &result {
            Ok(check) => caches.pending_remote.store(
                matches!(
                    check.decision,
                    nyaterm_core::CloudRemoteCheckDecision::AutoPull
                        | nyaterm_core::CloudRemoteCheckDecision::RemoteAvailable
                        | nyaterm_core::CloudRemoteCheckDecision::Conflict
                ),
                Ordering::Release,
            ),
            Err(_) => caches.pending_remote.store(true, Ordering::Release),
        }
        result
    })
}

pub(crate) fn push_checked_provider_snapshot(
    store: &StoreBlockingClient,
    settings: &CloudSyncSettings,
    options: &LocalCloudSyncOptions,
    checked: cloud_sync::CloudSyncCheck,
    control: &CloudSyncOperationControl,
) -> Result<CloudSyncResult, CloudSyncError> {
    with_remote(store, settings, options, "push", |remote, _| {
        checked.push(store, options, remote, control)
    })
}

pub(crate) fn pull_checked_provider_snapshot(
    store: &StoreBlockingClient,
    settings: &CloudSyncSettings,
    options: &LocalCloudSyncOptions,
    checked: cloud_sync::CloudSyncCheck,
    before_apply: &dyn Fn() -> Result<(), CloudSyncError>,
    control: &CloudSyncOperationControl,
) -> Result<CloudSyncResult, CloudSyncError> {
    with_remote(store, settings, options, "pull", |remote, _| {
        checked.pull(store, options, remote, before_apply, control)
    })
}

pub(in crate::features) fn test_provider_connection(
    local_store: &StoreBlockingClient,
    settings: &CloudSyncSettings,
    control: &CloudSyncOperationControl,
) -> Result<(), CloudSyncError> {
    control.checkpoint()?;
    with_provider_remote!(
        local_store,
        settings,
        None,
        "connection_test",
        remote,
        caches,
        {
            cloud_sync::load_sync_pointer_from_remote(
                &control.local_store(local_store),
                &control.remote(&remote),
                &settings.remote_root,
            )?;
            control.checkpoint()
        }
    )
}

pub(crate) fn push_provider_snapshot(
    local_store: &StoreBlockingClient,
    settings: &CloudSyncSettings,
    options: &LocalCloudSyncOptions,
    state: &CloudSyncState,
    force: bool,
    control: &CloudSyncOperationControl,
) -> Result<CloudSyncResult, CloudSyncError> {
    control.checkpoint()?;
    if !force {
        // Match the automatic push path: finish the remote inspection with one
        // HTTP client, then publish with a fresh one. Some WebDAV gateways stop
        // accepting mutations on a connection pool after the inspection reads,
        // which made manual push fail while a later automatic push succeeded.
        let checked = check_provider_snapshot(local_store, settings, options, state, control)?;
        return push_checked_provider_snapshot(local_store, settings, options, checked, control);
    }
    with_remote(local_store, settings, options, "push", |remote, _| {
        cloud_sync::push_snapshot_with_remote_controlled(
            local_store,
            options,
            remote,
            state,
            force,
            control,
        )
    })
}

pub(crate) fn pull_provider_snapshot(
    local_store: &StoreBlockingClient,
    settings: &CloudSyncSettings,
    options: &LocalCloudSyncOptions,
    state: &CloudSyncState,
    force: bool,
    control: &CloudSyncOperationControl,
) -> Result<CloudSyncResult, CloudSyncError> {
    pull_provider_snapshot_guarded(
        local_store,
        settings,
        options,
        state,
        force,
        &|| Ok(()),
        control,
    )
}

pub(crate) fn pull_provider_snapshot_guarded(
    local_store: &StoreBlockingClient,
    settings: &CloudSyncSettings,
    options: &LocalCloudSyncOptions,
    state: &CloudSyncState,
    force: bool,
    before_apply: &dyn Fn() -> Result<(), CloudSyncError>,
    control: &CloudSyncOperationControl,
) -> Result<CloudSyncResult, CloudSyncError> {
    control.checkpoint()?;
    with_remote(local_store, settings, options, "pull", |remote, _| {
        cloud_sync::pull_snapshot_with_remote_controlled(
            local_store,
            options,
            remote,
            state,
            force,
            before_apply,
            control,
        )
    })
}

pub(in crate::features) fn recover_provider_snapshot(
    local_store: &StoreBlockingClient,
    settings: &CloudSyncSettings,
    options: &LocalCloudSyncOptions,
    control: &CloudSyncOperationControl,
) -> Result<CloudSyncResult, CloudSyncError> {
    control.checkpoint()?;
    with_remote(local_store, settings, options, "recover", |remote, _| {
        cloud_sync::recover_current_snapshot_with_remote_controlled(
            local_store,
            options,
            remote,
            control,
        )
    })
}

pub(in crate::features) fn cleanup_provider_snapshots(
    local_store: &StoreBlockingClient,
    settings: &CloudSyncSettings,
    options: &LocalCloudSyncOptions,
    latest: Option<&RemoteSyncPointer>,
    control: &CloudSyncOperationControl,
) -> Result<(), CloudSyncError> {
    control.checkpoint()?;
    with_remote(local_store, settings, options, "cleanup", |remote, _| {
        cloud_sync::cleanup_sync_snapshots_with_remote_controlled(
            local_store,
            options,
            remote,
            latest,
            control,
        )
    })
}

pub(in crate::features) fn resolve_provider_conflict(
    store: &StoreBlockingClient,
    settings: &CloudSyncSettings,
    options: &LocalCloudSyncOptions,
    state: &CloudSyncState,
    request: &nyaterm_core::cloud_sync::conflict::CloudResolutionRequest,
    control: &CloudSyncOperationControl,
) -> Result<CloudSyncResult, CloudSyncError> {
    with_remote(store, settings, options, "resolve", |remote, _| {
        nyaterm_core::cloud_sync::conflict::resolve_with_remote(
            store,
            options,
            remote,
            state,
            request,
            &|| Ok(()),
            control,
        )
    })
}

#[cfg(test)]
mod tests {
    use super::{check_provider_snapshot, push_checked_provider_snapshot, push_provider_snapshot};
    use crate::features::sync::operation::lock_cloud_sync_operation;
    use crate::test_support::{TestConfigDir, blocking_test_store};
    use nyaterm_core::cloud_sync::control::CloudSyncOperationControl;
    use nyaterm_core::{
        CloudSyncOutcome, CloudSyncSettings, LocalCloudSyncOptions, SavedConnection,
        WebdavSyncSettings,
    };
    use nyaterm_store::StoreDomain;
    use serde_json::json;

    fn required_env(name: &str) -> String {
        std::env::var(name).unwrap_or_else(|_| panic!("{name} must be set"))
    }

    fn save_connection(store: &nyaterm_store::StoreBlockingClient, name: &str) {
        let connection: SavedConnection = serde_json::from_value(json!({
            "id": "webdav-live-test",
            "type": "ssh",
            "name": name,
            "host": "example.test",
            "port": 22,
            "username": "fixture"
        }))
        .expect("live-test connection");
        store
            .request_fn(StoreDomain::CloudSync, move |store| {
                store.save_connection(&connection)
            })
            .expect("save live-test connection");
    }

    #[test]
    #[ignore = "requires NYATERM_TEST_WEBDAV_* credentials and a disposable WebDAV root"]
    fn webdav_manual_push_survives_repeated_inspection_and_publish_sessions() {
        let endpoint = required_env("NYATERM_TEST_WEBDAV_ENDPOINT");
        let username = required_env("NYATERM_TEST_WEBDAV_USERNAME");
        let password = required_env("NYATERM_TEST_WEBDAV_PASSWORD");
        let remote_root = required_env("NYATERM_TEST_WEBDAV_ROOT");
        let dir = TestConfigDir::new("nyaterm-webdav-live-manual-push");
        let store = blocking_test_store(dir.path());
        let settings = CloudSyncSettings {
            protocol_version: 3,
            enabled: true,
            provider: "webdav".into(),
            remote_root: format!("manual-push-{}", uuid::Uuid::new_v4()),
            webdav: WebdavSyncSettings {
                endpoint,
                root: remote_root,
                username,
                password: Some(password.into()),
            },
            ..Default::default()
        };
        let saved = settings.clone();
        store
            .request_fn(StoreDomain::CloudSync, move |store| {
                store.save_master_password(Some("nyaterm-webdav-live-test"))?;
                store.save_cloud_sync_settings(saved)
            })
            .expect("save live-test cloud sync settings");
        let state = store
            .request_fn(StoreDomain::CloudSync, |store| {
                store.load_cloud_sync_state()
            })
            .expect("load live-test state");
        let options = LocalCloudSyncOptions {
            device_name: Some(settings.device_name.clone()),
            config_dir: dir.path().into(),
            portable_key_path: None,
            remote_dir: dir.join("cloud-sync-local"),
            remote_root: settings.remote_root.clone(),
            device_id: state.device_id.clone(),
            app_version: env!("CARGO_PKG_VERSION").into(),
            master_password: "nyaterm-webdav-live-test".into(),
            enabled: true,
        };
        let control = CloudSyncOperationControl::default();
        let _operation = lock_cloud_sync_operation(&control).expect("cloud sync operation lock");

        for index in 0..4 {
            save_connection(&store, &format!("Manual push {index}"));
            let state = store
                .request_fn(StoreDomain::CloudSync, |store| {
                    store.load_cloud_sync_state()
                })
                .expect("reload live-test state");
            let result =
                push_provider_snapshot(&store, &settings, &options, &state, false, &control)
                    .expect("manual WebDAV push");
            assert_eq!(result.outcome, CloudSyncOutcome::Uploaded);
        }

        save_connection(&store, "Automatic-style push");
        let state = store
            .request_fn(StoreDomain::CloudSync, |store| {
                store.load_cloud_sync_state()
            })
            .expect("reload live-test state");
        let checked = check_provider_snapshot(&store, &settings, &options, &state, &control)
            .expect("automatic-style WebDAV check");
        let result = push_checked_provider_snapshot(&store, &settings, &options, checked, &control)
            .expect("automatic-style WebDAV push");
        assert_eq!(result.outcome, CloudSyncOutcome::Uploaded);
    }
}
