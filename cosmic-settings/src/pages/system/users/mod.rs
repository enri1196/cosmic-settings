// Copyright 2024 System76 <info@system76.com>
// SPDX-License-Identifier: GPL-3.0-only

mod backend;
mod classic;
#[cfg(feature = "homed")]
mod homed;

use crate::pages;
use cosmic::{
    Apply, Element,
    dialog::file_chooser,
    iced::{Alignment, Length},
    widget::{self, Space, column, icon, row, settings, text},
};
use cosmic_settings_page::{self as page, Section, section};
use regex::Regex;
use slab::Slab;
use slotmap::SlotMap;
use std::{collections::HashSet, path::PathBuf, sync::Arc};
use url::Url;

const DEFAULT_ICON_FILE: &str = "/usr/share/pixmaps/faces/pop-robot.png";
const MIN_PASSWORD_LEN: usize = 8;

#[derive(Clone, Debug, Default)]
pub struct User {
    id: u64,
    profile_icon: Option<icon::Handle>,
    full_name: String,
    username: String,
    old_password: String,
    password: String,
    password_confirm: String,
    full_name_edit: bool,
    username_edit: bool,
    is_admin: bool,
    backend: backend::UserBackendKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EditorField {
    FullName,
    Username,
}

#[derive(Clone, Debug)]
pub enum HomedAction {
    SetAdmin {
        user: backend::UserEntry,
        is_admin: bool,
    },
    SetFullName {
        user: backend::UserEntry,
        full_name: String,
    },
    SetProfileIcon {
        user: backend::UserEntry,
        path: PathBuf,
    },
}

#[derive(Clone, Debug)]
pub enum Dialog {
    AddNewUser(User),
    UpdatePassword(User),
    HomedAuth {
        action: HomedAction,
        password: String,
    },
}

#[derive(Clone, Debug)]
pub struct Page {
    on_enter_handle: Option<cosmic::iced::task::Handle>,
    current_user_id: u64,
    entity: page::Entity,
    users: Vec<User>,
    selected_user_idx: Option<usize>,
    dialog: Option<Dialog>,
    homed_available: bool,
    default_icon: icon::Handle,
    current_password_label: String,
    password_label: String,
    password_confirm_label: String,
    username_label: String,
    fullname_label: String,
    current_password_hidden: bool,
    password_hidden: bool,
    password_confirm_hidden: bool,
}

impl Default for Page {
    fn default() -> Self {
        Self {
            on_enter_handle: None,
            current_user_id: 0,
            entity: page::Entity::default(),
            users: Vec::default(),
            selected_user_idx: None,
            dialog: None,
            homed_available: false,
            default_icon: icon::from_path(PathBuf::from(DEFAULT_ICON_FILE)),
            current_password_label: fl!("current-password"),
            password_label: fl!("password"),
            password_confirm_label: fl!("password-confirm"),
            username_label: fl!("username"),
            fullname_label: fl!("full-name"),
            current_password_hidden: true,
            password_hidden: true,
            password_confirm_hidden: true,
        }
    }
}

impl From<backend::UserEntry> for User {
    fn from(entry: backend::UserEntry) -> Self {
        Self {
            id: entry.id,
            profile_icon: entry.profile_icon.map(icon::from_path),
            full_name: entry.full_name,
            username: entry.username,
            is_admin: entry.is_admin,
            backend: entry.backend,
            ..Default::default()
        }
    }
}

impl User {
    fn to_entry(&self) -> backend::UserEntry {
        backend::UserEntry {
            id: self.id,
            username: self.username.clone(),
            full_name: self.full_name.clone(),
            is_admin: self.is_admin,
            profile_icon: None,
            backend: self.backend,
        }
    }
}

#[derive(Clone, Debug)]
pub enum Message {
    ApplyEdit(usize, EditorField),
    ChangedAccountType(u64, bool),
    DeletedUser(u64),
    Dialog(Option<Dialog>),
    Edit(usize, EditorField, String),
    LoadedIcon(u64, icon::Handle),
    LoadPage(u64, Vec<User>, bool),
    HomedAuthRequested(HomedAction),
    HomedAuthSubmit(HomedAction, String),
    NewUser(String, String, String, bool),
    None,
    SelectProfileImage(u64),
    SelectedProfileImage(u64, Arc<Result<Url, file_chooser::Error>>),
    SelectUser(usize),
    SelectedUserDelete(u64),
    SelectedUserSetAdmin(u64, bool),
    ToggleEdit(usize, EditorField),
    ToggleCurrentPasswordVisibility,
    TogglePasswordVisibility,
    TogglePasswordConfirmVisibility,
    SaveNewPassword(User),
}

impl From<Message> for crate::app::Message {
    fn from(message: Message) -> Self {
        crate::pages::Message::User(message).into()
    }
}

impl From<Message> for crate::pages::Message {
    fn from(message: Message) -> Self {
        crate::pages::Message::User(message)
    }
}

impl page::Page<crate::pages::Message> for Page {
    fn set_id(&mut self, entity: page::Entity) {
        self.entity = entity;
    }

    fn content(
        &self,
        sections: &mut SlotMap<section::Entity, Section<crate::pages::Message>>,
    ) -> Option<page::Content> {
        Some(vec![sections.insert(user_list())])
    }

    fn info(&self) -> page::Info {
        page::Info::new("users", "system-users-symbolic")
            .title(fl!("users"))
            .description(fl!("users", "desc"))
    }

    fn dialog(&self) -> Option<Element<'_, pages::Message>> {
        let dialog = self.dialog.as_ref()?;

        let dialog_element = match dialog {
            Dialog::AddNewUser(user) => {
                let full_name_input = widget::container(
                    widget::text_input("", &user.full_name)
                        .label(&self.fullname_label)
                        .on_input(|value| {
                            Message::Dialog(Some(Dialog::AddNewUser(User {
                                full_name: value,
                                ..user.clone()
                            })))
                        }),
                );

                let username_input = widget::container(
                    widget::text_input("", &user.username)
                        .label(&self.username_label)
                        .on_input(|value| {
                            Message::Dialog(Some(Dialog::AddNewUser(User {
                                username: value,
                                ..user.clone()
                            })))
                        }),
                );

                let password_input = widget::container(
                    widget::secure_input(
                        "",
                        &user.password,
                        Some(Message::TogglePasswordVisibility),
                        self.password_hidden,
                    )
                    .label(&self.password_label)
                    .on_input(|value| {
                        Message::Dialog(Some(Dialog::AddNewUser(User {
                            password: value,
                            ..user.clone()
                        })))
                    }),
                );

                let password_confirm_input = widget::container(
                    widget::secure_input(
                        "",
                        &user.password_confirm,
                        Some(Message::TogglePasswordConfirmVisibility),
                        self.password_confirm_hidden,
                    )
                    .label(&self.password_confirm_label)
                    .on_input(|value| {
                        Message::Dialog(Some(Dialog::AddNewUser(User {
                            password_confirm: value,
                            ..user.clone()
                        })))
                    }),
                );

                let admin_toggler = widget::toggler(user.is_admin).on_toggle(|value| {
                    Message::Dialog(Some(Dialog::AddNewUser(User {
                        is_admin: value,
                        ..user.clone()
                    })))
                });

                // validation
                let mut validation_msg = String::new();
                let username_regex = Regex::new("^[a-z][a-z0-9-]{0,30}$").unwrap();
                let username_valid = username_regex.is_match(&user.username);
                let password_too_short = self.homed_available
                    && !user.password.is_empty()
                    && user.password.chars().count() < MIN_PASSWORD_LEN;
                let complete_maybe = if !username_valid && !user.username.is_empty() {
                    validation_msg = fl!("invalid-username");
                    None
                } else if user.password != user.password_confirm
                    && !user.password.is_empty()
                    && !user.password_confirm.is_empty()
                {
                    validation_msg = fl!("password-mismatch");
                    None
                } else if password_too_short {
                    // homed wants minimum 8 chars
                    validation_msg = fl!("password-too-short", min = MIN_PASSWORD_LEN);
                    None
                } else if user.full_name.is_empty()
                    || user.username.is_empty()
                    || user.password.is_empty()
                    || user.password_confirm.is_empty()
                {
                    None
                } else {
                    Some(Message::NewUser(
                        user.username.clone(),
                        user.full_name.clone(),
                        user.password.clone(),
                        user.is_admin,
                    ))
                };

                let add_user_button = widget::button::suggested(fl!("add-user"))
                    .on_press_maybe(complete_maybe)
                    .apply(Element::from);

                let cancel_button =
                    widget::button::standard(fl!("cancel")).on_press(Message::Dialog(None));

                widget::dialog()
                    .title(fl!("add-user"))
                    .control(
                        widget::ListColumn::default()
                            .add(full_name_input)
                            .add(username_input)
                            .add(password_input)
                            .add(password_confirm_input)
                            .add(
                                row::with_capacity(3)
                                    .push(
                                        column::with_capacity(2)
                                            .push(text::body(crate::fl!("administrator")))
                                            .push(text::caption(crate::fl!(
                                                "administrator",
                                                "desc"
                                            )))
                                            .width(Length::Fill),
                                    )
                                    .push(Space::new(5, 0))
                                    .push(admin_toggler)
                                    .align_y(Alignment::Center),
                            ),
                    )
                    .primary_action(add_user_button)
                    .secondary_action(cancel_button)
                    .tertiary_action(widget::text::body(validation_msg))
                    .apply(Element::from)
            }

            Dialog::UpdatePassword(user) => {
                let needs_current_password = user.backend == backend::UserBackendKind::Homed;

                let old_password_input = widget::container(
                    widget::secure_input(
                        "",
                        &user.old_password,
                        Some(Message::ToggleCurrentPasswordVisibility),
                        self.current_password_hidden,
                    )
                    .label(&self.current_password_label)
                    .on_input(|value| {
                        Message::Dialog(Some(Dialog::UpdatePassword(User {
                            old_password: value,
                            ..user.clone()
                        })))
                    }),
                );

                let password_input = widget::container(
                    widget::secure_input(
                        "",
                        &user.password,
                        Some(Message::TogglePasswordVisibility),
                        self.password_hidden,
                    )
                    .label(&self.password_label)
                    .on_input(|value| {
                        Message::Dialog(Some(Dialog::UpdatePassword(User {
                            password: value,
                            ..user.clone()
                        })))
                    }),
                );

                let password_confirm_input = widget::container(
                    widget::secure_input(
                        "",
                        &user.password_confirm,
                        Some(Message::TogglePasswordConfirmVisibility),
                        self.password_confirm_hidden,
                    )
                    .label(&self.password_confirm_label)
                    .on_input(|value| {
                        Message::Dialog(Some(Dialog::UpdatePassword(User {
                            password_confirm: value,
                            ..user.clone()
                        })))
                    }),
                );

                // validation
                let mut validation_msg = String::new();
                let has_new_password_input =
                    !user.password.is_empty() || !user.password_confirm.is_empty();
                let current_password_missing =
                    needs_current_password && user.old_password.is_empty();
                let password_too_short = needs_current_password
                    && !user.password.is_empty()
                    && user.password.chars().count() < MIN_PASSWORD_LEN;
                let password_same_as_old = needs_current_password
                    && !user.password.is_empty()
                    && !user.password_confirm.is_empty()
                    && !user.old_password.is_empty()
                    && user.password == user.old_password;
                let complete_maybe = if user.password != user.password_confirm
                    && !user.password.is_empty()
                    && !user.password_confirm.is_empty()
                {
                    validation_msg = fl!("password-mismatch");
                    None
                } else if password_same_as_old {
                    validation_msg = fl!("password-same-as-current");
                    None
                } else if password_too_short {
                    // homed wants minimum 8 chars
                    validation_msg = fl!("password-too-short", min = MIN_PASSWORD_LEN);
                    None
                } else if current_password_missing && has_new_password_input {
                    validation_msg = fl!("current-password-required");
                    None
                } else if user.password.is_empty() || user.password_confirm.is_empty() {
                    None
                } else if current_password_missing {
                    None
                } else {
                    Some(Message::SaveNewPassword(user.clone()))
                };

                let save_button = widget::button::suggested(fl!("save"))
                    .on_press_maybe(complete_maybe)
                    .apply(Element::from);

                let cancel_button =
                    widget::button::standard(fl!("cancel")).on_press(Message::Dialog(None));

                widget::dialog()
                    .title(fl!("change-password"))
                    .control({
                        let mut column = widget::ListColumn::default();
                        if needs_current_password {
                            column = column.add(old_password_input);
                        }
                        column.add(password_input).add(password_confirm_input)
                    })
                    .primary_action(save_button)
                    .secondary_action(cancel_button)
                    .tertiary_action(widget::text::body(validation_msg))
                    .apply(Element::from)
            }

            Dialog::HomedAuth { action, password } => {
                let password_input = widget::container(
                    widget::secure_input(
                        "",
                        password,
                        Some(Message::ToggleCurrentPasswordVisibility),
                        self.current_password_hidden,
                    )
                    .label(&self.current_password_label)
                    .on_input(|value| {
                        Message::Dialog(Some(Dialog::HomedAuth {
                            action: action.clone(),
                            password: value,
                        }))
                    }),
                );

                let complete_maybe = if password.is_empty() {
                    None
                } else {
                    Some(Message::HomedAuthSubmit(action.clone(), password.clone()))
                };

                let save_button = widget::button::suggested(fl!("save"))
                    .on_press_maybe(complete_maybe)
                    .apply(Element::from);

                let cancel_button =
                    widget::button::standard(fl!("cancel")).on_press(Message::Dialog(None));

                widget::dialog()
                    .title(fl!("authentication-required"))
                    .control(widget::ListColumn::default().add(password_input))
                    .primary_action(save_button)
                    .secondary_action(cancel_button)
                    .apply(Element::from)
            }
        };

        dialog_element.map(crate::pages::Message::User).into()
    }

    fn on_enter(&mut self) -> cosmic::Task<crate::pages::Message> {
        if let Some(handle) = self.on_enter_handle.take() {
            handle.abort();
        }

        let (task, handle) = cosmic::task::future(async { Self::reload().await }).abortable();
        self.on_enter_handle = Some(handle);
        task
    }

    fn on_leave(&mut self) -> cosmic::Task<crate::pages::Message> {
        if let Some(handle) = self.on_enter_handle.take() {
            handle.abort();
        }

        cosmic::Task::none()
    }
}

impl Page {
    pub async fn reload() -> Message {
        let uid = rustix::process::getuid().as_raw() as u64;
        let mut users = Vec::new();
        let mut seen_ids = HashSet::new();

        for backend in backend::active_backends().await {
            match backend.list_users().await {
                Ok(entries) => {
                    for entry in entries {
                        if seen_ids.insert(entry.id) {
                            users.push(User::from(entry));
                        }
                    }
                }
                Err(why) => {
                    tracing::error!(?why, "failed to list users for backend");
                }
            }
        }

        let mut homed_available = false;
        #[cfg(feature = "homed")]
        {
            homed_available = backend::HomedBackend::try_new().await.is_some();
        }

        Message::LoadPage(uid, users, homed_available)
    }

    pub fn update(&mut self, message: Message) -> cosmic::Task<crate::app::Message> {
        match message {
            Message::None => (),

            Message::ChangedAccountType(uid, is_admin) => {
                for user in &mut self.users {
                    if user.id == uid {
                        user.is_admin = is_admin;
                        return cosmic::Task::none();
                    }
                }
            }

            Message::LoadedIcon(uid, handle) => {
                for user in &mut self.users {
                    if user.id == uid {
                        user.profile_icon = Some(handle);
                        return cosmic::Task::none();
                    }
                }
            }

            Message::HomedAuthRequested(action) => {
                self.password_hidden = true;
                self.password_confirm_hidden = true;
                self.current_password_hidden = true;
                self.dialog = Some(Dialog::HomedAuth {
                    action,
                    password: String::new(),
                });
            }

            Message::HomedAuthSubmit(action, password) => {
                self.dialog = None;

                return cosmic::task::future(async move {
                    match action {
                        HomedAction::SetAdmin { user, is_admin } => {
                            let Some(backend) = backend::backend_for_kind(user.backend).await
                            else {
                                return Message::None;
                            };

                            if let Err(why) = backend
                                .set_admin(&user, is_admin, Some(password.as_str()))
                                .await
                            {
                                tracing::error!(?why, "failed to change account type of user");
                                return Message::None;
                            }

                            Message::ChangedAccountType(user.id, is_admin)
                        }
                        HomedAction::SetFullName { user, full_name } => {
                            let Some(backend) = backend::backend_for_kind(user.backend).await
                            else {
                                return Message::None;
                            };

                            if let Err(why) = backend
                                .set_full_name(&user, &full_name, Some(password.as_str()))
                                .await
                            {
                                tracing::error!(?why, "failed to set full name");
                            }

                            Message::None
                        }
                        HomedAction::SetProfileIcon { user, path } => {
                            let Some(backend) = backend::backend_for_kind(user.backend).await
                            else {
                                return Message::None;
                            };

                            if let Err(why) = backend
                                .set_profile_icon(&user, &path, Some(password.as_str()))
                                .await
                            {
                                tracing::error!(?why, "failed to set profile icon");
                                return Message::None;
                            }

                            Message::LoadedIcon(user.id, icon::from_path(path))
                        }
                    }
                });
            }

            Message::SelectProfileImage(uid) => {
                return cosmic::task::future(async move {
                    let dialog_result = file_chooser::open::Dialog::new()
                        .title(fl!("users", "profile-add"))
                        .accept_label(fl!("dialog-add"))
                        .modal(false)
                        .open_file()
                        .await
                        .map(|response| response.url().to_owned());

                    Message::SelectedProfileImage(uid, Arc::new(dialog_result))
                });
            }

            Message::SelectedProfileImage(uid, image_result) => {
                let Some(user_entry) = self
                    .users
                    .iter()
                    .find(|user| user.id == uid)
                    .map(User::to_entry)
                else {
                    return cosmic::Task::none();
                };

                let url = match Arc::into_inner(image_result).unwrap() {
                    Ok(url) => url,
                    Err(why) => {
                        tracing::error!(?why, "failed to get image file");
                        return cosmic::Task::none();
                    }
                };

                return cosmic::task::future(async move {
                    let Ok(path) = url.to_file_path() else {
                        tracing::error!("selected image is not a file path");
                        return Message::None;
                    };

                    if user_entry.backend == backend::UserBackendKind::Homed {
                        return Message::HomedAuthRequested(HomedAction::SetProfileIcon {
                            user: user_entry,
                            path,
                        });
                    }

                    let Some(backend) = backend::backend_for_kind(user_entry.backend).await else {
                        return Message::None;
                    };

                    if let Err(why) = backend.set_profile_icon(&user_entry, &path, None).await {
                        tracing::error!(?why, "failed to set profile icon");
                        return Message::None;
                    }

                    Message::LoadedIcon(uid, icon::from_path(path))
                });
            }

            Message::Edit(id, field, value) => {
                if let Some(user) = self.users.get_mut(id) {
                    match field {
                        EditorField::FullName => user.full_name = value,
                        EditorField::Username => user.username = value,
                    }
                }
            }

            Message::ToggleEdit(id, field) => {
                if let Some(user) = self.users.get_mut(id) {
                    if matches!(field, EditorField::Username)
                        && user.backend != backend::UserBackendKind::Classic
                    {
                        return cosmic::Task::none();
                    }

                    match field {
                        EditorField::FullName => user.full_name_edit = !user.full_name_edit,
                        EditorField::Username => user.username_edit = !user.username_edit,
                    }
                }
            }

            Message::TogglePasswordVisibility => {
                self.password_hidden = !self.password_hidden;
            }
            Message::TogglePasswordConfirmVisibility => {
                self.password_confirm_hidden = !self.password_confirm_hidden;
            }
            Message::ToggleCurrentPasswordVisibility => {
                self.current_password_hidden = !self.current_password_hidden;
            }

            Message::ApplyEdit(id, field) => {
                if let Some(user) = self.users.get_mut(id) {
                    let user_entry = user.to_entry();

                    match field {
                        EditorField::FullName => {
                            if user.full_name_edit {
                                let user_entry = user_entry.clone();
                                let full_name = user.full_name.clone();

                                if user.backend == backend::UserBackendKind::Homed {
                                    self.password_hidden = true;
                                    self.password_confirm_hidden = true;
                                    self.dialog = Some(Dialog::HomedAuth {
                                        action: HomedAction::SetFullName {
                                            user: user_entry,
                                            full_name,
                                        },
                                        password: String::new(),
                                    });
                                    return cosmic::Task::none();
                                }

                                return cosmic::Task::future(async move {
                                    let Some(backend) =
                                        backend::backend_for_kind(user_entry.backend).await
                                    else {
                                        return;
                                    };

                                    if let Err(why) =
                                        backend.set_full_name(&user_entry, &full_name, None).await
                                    {
                                        tracing::error!(?why, "failed to set full name");
                                    }
                                })
                                .discard();
                            }
                        }

                        EditorField::Username => {
                            if user.backend != backend::UserBackendKind::Classic {
                                return cosmic::Task::none();
                            }

                            if user.username_edit {
                                let user_entry = user_entry.clone();
                                let username = user.username.clone();

                                return cosmic::Task::future(async move {
                                    let Some(backend) =
                                        backend::backend_for_kind(user_entry.backend).await
                                    else {
                                        return;
                                    };

                                    if let Err(why) =
                                        backend.set_username(&user_entry, &username).await
                                    {
                                        tracing::error!(?why, "failed to set username");
                                    }
                                })
                                .discard();
                            }
                        }
                    }
                }
            }

            Message::SaveNewPassword(user) => {
                self.dialog = None;

                let user_entry = user.to_entry();
                let password = user.password.clone();
                let old_password = if user.backend == backend::UserBackendKind::Homed {
                    Some(user.old_password.clone())
                } else {
                    None
                };

                return cosmic::Task::future(async move {
                    let Some(backend) = backend::backend_for_kind(user_entry.backend).await else {
                        return;
                    };

                    if let Err(why) = backend
                        .set_password(&user_entry, &password, old_password.as_deref())
                        .await
                    {
                        tracing::error!(?why, "failed to set password");
                    }
                })
                .discard();
            }

            Message::LoadPage(uid, users, homed_available) => {
                self.current_user_id = uid;
                self.users = users;
                self.homed_available = homed_available;
            }

            Message::SelectUser(user_idx) => {
                match self.selected_user_idx {
                    Some(currently_selected_idx) if currently_selected_idx == user_idx => {
                        self.selected_user_idx = None;
                    }
                    _ => {
                        self.selected_user_idx = Some(user_idx);
                    }
                };
            }

            Message::SelectedUserDelete(uid) => {
                let Some(user_entry) = self
                    .users
                    .iter()
                    .find(|user| user.id == uid)
                    .map(User::to_entry)
                else {
                    return cosmic::Task::none();
                };

                return cosmic::task::future(async move {
                    let Some(backend) = backend::backend_for_kind(user_entry.backend).await else {
                        return Message::None;
                    };

                    if let Err(why) = backend.delete_user(&user_entry).await {
                        tracing::error!(?why, "failed to delete user account");
                        return Message::None;
                    }

                    Message::DeletedUser(uid)
                });
            }

            Message::DeletedUser(uid) => {
                self.users.retain(|user| user.id != uid);
            }

            Message::Dialog(dialog) => {
                self.current_password_hidden = true;
                self.password_hidden = true;
                self.password_confirm_hidden = true;
                self.dialog = dialog;
            }

            Message::NewUser(username, full_name, password, is_admin) => {
                self.dialog = None;

                return cosmic::task::future(async move {
                    let Some(backend) = backend::preferred_backend().await else {
                        return Message::None;
                    };

                    if let Err(why) = backend
                        .create_user(&username, &full_name, &password, is_admin)
                        .await
                    {
                        tracing::error!(?why, "failed to create user account");
                        return Message::None;
                    }

                    Self::reload().await
                });
            }

            Message::SelectedUserSetAdmin(uid, is_admin) => {
                let Some(user_entry) = self
                    .users
                    .iter()
                    .find(|user| user.id == uid)
                    .map(User::to_entry)
                else {
                    return cosmic::Task::none();
                };

                // if user_entry.backend != backend::UserBackendKind::Classic {
                //     return cosmic::Task::none();
                // }

                if user_entry.backend == backend::UserBackendKind::Homed {
                    self.password_hidden = true;
                    self.password_confirm_hidden = true;
                    self.dialog = Some(Dialog::HomedAuth {
                        action: HomedAction::SetAdmin {
                            user: user_entry,
                            is_admin,
                        },
                        password: String::new(),
                    });
                    return cosmic::Task::none();
                }

                return cosmic::task::future(async move {
                    let Some(backend) = backend::backend_for_kind(user_entry.backend).await else {
                        return Message::None;
                    };

                    if let Err(why) = backend.set_admin(&user_entry, is_admin, None).await {
                        tracing::error!(?why, "failed to change account type of user");
                        return Message::None;
                    }

                    Message::ChangedAccountType(uid, is_admin)
                });
            }
        };

        cosmic::Task::none()
    }
}

impl page::AutoBind<crate::pages::Message> for Page {}

fn user_list() -> Section<crate::pages::Message> {
    let mut descriptions = Slab::new();

    let user_type_standard = descriptions.insert(fl!("users", "standard"));
    let user_type_admin = descriptions.insert(fl!("users", "admin"));

    Section::default()
        .descriptions(descriptions)
        .view::<Page>(move |_binder, page, section| {
            let descriptions = &section.descriptions;

            let cosmic::cosmic_theme::Spacing {
                space_xxs, space_m, ..
            } = cosmic::theme::active().cosmic().spacing;

            let users_list = page
                .users
                .iter()
                .enumerate()
                .flat_map(|(idx, user)| {
                    let expanded =
                        matches!(page.selected_user_idx, Some(user_idx) if user_idx == idx);
                    let is_classic = user.backend == backend::UserBackendKind::Classic;

                    let username = if is_classic {
                        widget::editable_input("", &user.username, user.username_edit, move |_| {
                            Message::ToggleEdit(idx, EditorField::Username)
                        })
                        .on_input(move |name| Message::Edit(idx, EditorField::Username, name))
                        .on_submit(move |_| Message::ApplyEdit(idx, EditorField::Username))
                        .on_unfocus(Message::ApplyEdit(idx, EditorField::Username))
                        .apply(Element::from)
                    } else {
                        text::body(&user.username).apply(Element::from)
                    };

                    let password = widget::button::standard(fl!("change-password"))
                        .on_press(Message::Dialog(Some(Dialog::UpdatePassword(user.clone()))))
                        .apply(Element::from);

                    let fullname = widget::editable_input(
                        "",
                        &user.full_name,
                        user.full_name_edit,
                        move |_| Message::ToggleEdit(idx, EditorField::FullName),
                    )
                    .on_input(move |name| Message::Edit(idx, EditorField::FullName, name))
                    .on_submit(move |_| Message::ApplyEdit(idx, EditorField::FullName))
                    .on_unfocus(Message::ApplyEdit(idx, EditorField::FullName))
                    .apply(Element::from);

                    let fullname_text = text::body(if !user.full_name.is_empty() {
                        &user.full_name
                    } else {
                        &user.username
                    });

                    let account_type = text::caption(if user.is_admin {
                        &descriptions[user_type_admin]
                    } else {
                        &descriptions[user_type_standard]
                    });

                    let expanded_details = expanded.then(|| {
                        let mut details_list = widget::list_column()
                            .add(settings::item(&page.fullname_label, fullname))
                            .add(settings::item(&page.username_label, username))
                            .add(settings::item(&page.password_label, password))
                            .add(settings::item_row(vec![
                                column::with_capacity(2)
                                    .push(text::body(crate::fl!("administrator")))
                                    .push(text::caption(crate::fl!("administrator", "desc")))
                                    .width(Length::Fill)
                                    .into(),
                                Space::new(5, 0).into(),
                                widget::toggler(user.is_admin)
                                    .on_toggle(|enabled| {
                                        Message::SelectedUserSetAdmin(user.id, enabled)
                                    })
                                    .into(),
                            ]));

                        if page.users.len() > 1 {
                            details_list = details_list.add(settings::item_row(vec![
                                widget::horizontal_space().width(Length::Fill).into(),
                                widget::button::destructive(crate::fl!("remove-user"))
                                    .on_press(Message::SelectedUserDelete(user.id))
                                    .into(),
                            ]));
                        }

                        details_list.apply(Element::from)
                    });

                    let profile_icon_handle = user
                        .profile_icon
                        .clone()
                        .unwrap_or_else(|| page.default_icon.clone());

                    let profile_icon = widget::button::icon(profile_icon_handle)
                        .large()
                        .padding(0)
                        .class(cosmic::theme::Button::Standard);

                    let profile_icon = profile_icon.on_press(Message::SelectProfileImage(user.id));

                    let account_details_content = settings::item_row(vec![
                        widget::row::with_capacity(2)
                            .push(profile_icon)
                            .push(
                                column::with_capacity(2)
                                    .push(fullname_text)
                                    .push(account_type),
                            )
                            .align_y(Alignment::Center)
                            .spacing(space_xxs)
                            .into(),
                        widget::horizontal_space().width(Length::Fill).into(),
                        icon::from_name(if expanded {
                            "go-up-symbolic"
                        } else {
                            "go-down-symbolic"
                        })
                        .icon()
                        .size(16)
                        .into(),
                    ]);

                    let account_details = Some(
                        widget::button::custom(account_details_content)
                            .padding([space_xxs, space_m])
                            .on_press(Message::SelectUser(idx))
                            .class(cosmic::theme::Button::ListItem)
                            .selected(expanded)
                            .apply(Element::from),
                    );

                    vec![account_details, expanded_details]
                })
                .flatten()
                .fold(
                    widget::list_column()
                        .spacing(0)
                        .padding([8, 0])
                        .divider_padding(0)
                        .list_item_padding(0),
                    widget::ListColumn::add,
                )
                .apply(|list| Element::from(settings::section::with_column(list)));

            let add_user = widget::button::standard(crate::fl!("add-user"))
                .on_press(Message::Dialog(Some(Dialog::AddNewUser(User::default()))))
                .apply(widget::container)
                .width(Length::Fill)
                .align_x(Alignment::End);

            widget::column::with_capacity(2)
                .push(users_list)
                .push(add_user)
                .spacing(space_m)
                .apply(Element::from)
                .map(crate::pages::Message::User)
        })
}
