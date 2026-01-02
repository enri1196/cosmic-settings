// Copyright 2024 System76 <info@system76.com>
// SPDX-License-Identifier: GPL-3.0-only

use super::{UserBackend, UserBackendKind, UserEntry, uid_range};
use crate::pages::system::users::backend::request_permission_on_denial;
use crate::pages::system::users::getent;
use anyhow::Context;
use image::GenericImageView;
use pwhash::{bcrypt, md5_crypt, sha256_crypt, sha512_crypt};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

// AccountsService has a hard limit of 1MB for icon files
// https://gitlab.freedesktop.org/accountsservice/accountsservice/-/blob/main/src/user.c#L3131
const MAX_ICON_SIZE_BYTES: u64 = 1_048_576;
// Use a smaller threshold to ensure compressed images stay under the limit
const ICON_SIZE_THRESHOLD: u64 = 900_000; // 900KB
// Target dimensions for resized profile icons
const TARGET_ICON_SIZE: u32 = 512;

#[derive(Debug, Default)]
pub struct ClassicBackend;

impl ClassicBackend {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl UserBackend for ClassicBackend {
    async fn list_users(&self) -> anyhow::Result<Vec<UserEntry>> {
        let passwd_users = getent::passwd(uid_range());
        let mut users = Vec::with_capacity(passwd_users.len());
        let groups = getent::group();

        let admin_group = groups.iter().find(|g| &*g.name == "sudo");

        let conn = zbus::Connection::system()
            .await
            .context("unable to access dbus system service")?;

        for user in passwd_users {
            let Ok(user_proxy) = accounts_zbus::UserProxy::from_uid(&conn, user.uid).await else {
                continue;
            };

            users.push(UserEntry {
                id: user.uid,
                profile_icon: user_proxy.icon_file().await.ok().map(PathBuf::from),
                is_admin: match user_proxy.account_type().await {
                    Ok(1) => true,
                    Ok(_) => false,
                    Err(_) => admin_group
                        .is_some_and(|group| group.users.contains(&user.username)),
                },
                username: String::from(user.username),
                full_name: String::from(user.full_name),
                backend: UserBackendKind::Classic,
            });
        }

        Ok(users)
    }

    async fn set_password(
        &self,
        user: &UserEntry,
        password: &str,
        _old_password: Option<&str>,
    ) -> anyhow::Result<()> {
        let conn = zbus::Connection::system().await?;
        let user_proxy = accounts_zbus::UserProxy::from_uid(&conn, user.id)
            .await
            .context("failed to get user proxy")?;
        let password_hashed = hash_password(password);

        request_permission_on_denial(&conn, || user_proxy.set_password(&password_hashed, ""))
            .await
            .context("failed to set password")?;

        Ok(())
    }

    async fn delete_user(&self, user: &UserEntry) -> anyhow::Result<()> {
        let conn = zbus::Connection::system().await?;
        let accounts = accounts_zbus::AccountsProxy::new(&conn)
            .await
            .context("failed to get accounts proxy")?;

        request_permission_on_denial(&conn, || accounts.delete_user(user.id as i64, false))
            .await
            .context("failed to delete user account")?;

        Ok(())
    }

    async fn set_admin(
        &self,
        user: &UserEntry,
        is_admin: bool,
        _auth_password: Option<&str>,
    ) -> anyhow::Result<()> {
        let conn = zbus::Connection::system().await?;
        let user_proxy = accounts_zbus::UserProxy::from_uid(&conn, user.id)
            .await
            .context("failed to get user proxy")?;

        request_permission_on_denial(&conn, || async {
            user_proxy.set_account_type(if is_admin { 1 } else { 0 }).await
        })
        .await
        .context("failed to change account type")?;

        Ok(())
    }

    async fn create_user(
        &self,
        username: &str,
        full_name: &str,
        password: &str,
        is_admin: bool,
    ) -> anyhow::Result<()> {
        let conn = zbus::Connection::system().await?;
        let accounts = accounts_zbus::AccountsProxy::new(&conn)
            .await
            .context("failed to get accounts proxy")?;

        let user_object_path = request_permission_on_denial(&conn, || {
            accounts.create_user(username, full_name, if is_admin { 1 } else { 0 })
        })
        .await
        .context("failed to create user account")?;

        let password_hashed = hash_password(password);
        let user = accounts_zbus::UserProxy::new(&conn, user_object_path)
            .await
            .context("failed to get user by object path")?;

        _ = user.set_password(&password_hashed, "").await;
        _ = user.set_icon_file(super::super::DEFAULT_ICON_FILE).await;

        Ok(())
    }

    async fn set_full_name(
        &self,
        user: &UserEntry,
        full_name: &str,
        _auth_password: Option<&str>,
    ) -> anyhow::Result<()> {
        let conn = zbus::Connection::system().await?;
        let user_proxy = accounts_zbus::UserProxy::from_uid(&conn, user.id)
            .await
            .context("failed to get user proxy")?;

        request_permission_on_denial(&conn, || user_proxy.set_real_name(full_name))
            .await
            .context("failed to set real name")?;

        Ok(())
    }

    async fn set_username(&self, user: &UserEntry, username: &str) -> anyhow::Result<()> {
        let conn = zbus::Connection::system().await?;
        let user_proxy = accounts_zbus::UserProxy::from_uid(&conn, user.id)
            .await
            .context("failed to get user proxy")?;

        request_permission_on_denial(&conn, || user_proxy.set_user_name(username))
            .await
            .context("failed to set username")?;

        Ok(())
    }

    async fn set_profile_icon(
        &self,
        user: &UserEntry,
        icon_path: &Path,
        _auth_password: Option<&str>,
    ) -> anyhow::Result<()> {
        let conn = zbus::Connection::system().await?;
        let user_proxy = accounts_zbus::UserProxy::from_uid(&conn, user.id)
            .await
            .context("failed to get user proxy")?;

        let icon_path = prepare_icon_file(icon_path).context("failed to prepare icon file")?;
        let icon_path = icon_path
            .to_str()
            .context("icon path is not valid UTF-8")?;

        request_permission_on_denial(&conn, || user_proxy.set_icon_file(icon_path))
        .await
        .context("failed to set profile icon")?;

        Ok(())
    }
}

fn prepare_icon_file(path: &Path) -> anyhow::Result<PathBuf> {
    let metadata = std::fs::metadata(path)?;
    let file_size = metadata.len();

    tracing::debug!("Icon file size: {} bytes", file_size);

    if file_size <= ICON_SIZE_THRESHOLD {
        tracing::debug!("File size is acceptable, using original file");
        return Ok(path.to_path_buf());
    }

    tracing::info!(
        "Icon file is {} bytes, resizing to fit under 1MB limit",
        file_size
    );

    let img = image::open(path)?;
    let (width, height) = img.dimensions();

    tracing::debug!("Original image dimensions: {}x{}", width, height);

    let (new_width, new_height) = if width > height {
        let ratio = TARGET_ICON_SIZE as f32 / width as f32;
        (TARGET_ICON_SIZE, (height as f32 * ratio) as u32)
    } else {
        let ratio = TARGET_ICON_SIZE as f32 / height as f32;
        ((width as f32 * ratio) as u32, TARGET_ICON_SIZE)
    };

    tracing::debug!("Resizing to {}x{}", new_width, new_height);

    let resized = img.resize(new_width, new_height, image::imageops::FilterType::Lanczos3);

    // Create a temporary file for the resized icon
    let temp_dir = std::env::temp_dir();
    let temp_filename = format!("cosmic-settings-icon-{}.png", std::process::id());
    let temp_path = temp_dir.join(temp_filename);

    tracing::debug!("Saving resized icon to: {:?}", temp_path);

    resized.save(&temp_path)?;

    let new_size = std::fs::metadata(&temp_path)?.len();
    tracing::info!("Resized icon file size: {} bytes", new_size);

    if new_size > MAX_ICON_SIZE_BYTES {
        tracing::warn!("Resized file is still too large, but attempting anyway");
    }

    Ok(temp_path)
}

// TODO: Should we allow deprecated methods?
fn hash_password(password_plain: &str) -> String {
    #[allow(deprecated)]
    match get_encrypt_method().as_str() {
        "SHA512" => sha512_crypt::hash(password_plain).unwrap(),
        "SHA256" => sha256_crypt::hash(password_plain).unwrap(),
        "MD5" => md5_crypt::hash(password_plain).unwrap(),
        _ => bcrypt::hash(password_plain).unwrap(),
    }
}

// TODO: In the future loading in the whole login.defs file into an object might be handy?
// For now, just grabbing what we need
fn get_encrypt_method() -> String {
    let mut value = String::new();
    let login_defs = if let Ok(file) = File::open("/etc/login.defs") {
        file
    } else {
        return value;
    };
    let reader = BufReader::new(login_defs);

    for line in reader.lines().map_while(Result::ok) {
        if !line.trim().is_empty()
            && let Some(index) = line.find(|c: char| c.is_whitespace())
        {
            let key = line[0..index].trim();
            if key == "ENCRYPT_METHOD" {
                value = line[(index + 1)..].trim().to_string();
            }
        }
    }
    value
}
