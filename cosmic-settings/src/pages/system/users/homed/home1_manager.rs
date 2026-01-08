use zbus::zvariant;

// TODO: temp proxy to allow interactive auth
// I should probably add this to dbus-settings crate
#[zbus::proxy(
    interface = "org.freedesktop.home1.Manager",
    default_service = "org.freedesktop.home1",
    default_path = "/org/freedesktop/home1"
)]
pub(crate) trait Home1Manager {
    #[zbus(name = "GetHomeByName")]
    fn get_home_by_name(
        &self,
        user_name: String,
    ) -> zbus::Result<(
        u32,
        String,
        u32,
        String,
        String,
        String,
        zvariant::OwnedObjectPath,
    )>;

    #[zbus(name = "GetUserRecordByName")]
    fn get_user_record_by_name(
        &self,
        user_name: String,
    ) -> zbus::Result<(String, bool, zvariant::OwnedObjectPath)>;

    #[zbus(name = "ListHomes")]
    fn list_homes(
        &self,
    ) -> zbus::Result<
        Vec<(
            String,
            u32,
            String,
            u32,
            String,
            String,
            String,
            zvariant::OwnedObjectPath,
        )>,
    >;

    #[zbus(name = "CreateHome", allow_interactive_auth)]
    fn create_home(&self, user_record: String) -> zbus::Result<()>;

    #[zbus(name = "UpdateHome", allow_interactive_auth)]
    fn update_home(&self, record: String) -> zbus::Result<()>;

    #[zbus(name = "UpdateHomeEx", allow_interactive_auth)]
    fn update_home_ex(
        &self,
        record: String,
        blobs: std::collections::HashMap<String, zbus::zvariant::OwnedFd>,
        flags: u64,
    ) -> zbus::Result<()>;

    #[zbus(name = "ChangePasswordHome", allow_interactive_auth)]
    fn change_password_home(
        &self,
        user_name: String,
        new_secret: String,
        old_secret: String,
    ) -> zbus::Result<()>;

    #[zbus(name = "UnlockHome", allow_interactive_auth)]
    fn unlock_home(&self, user_name: String, secret: String) -> zbus::Result<()>;

    #[zbus(name = "RemoveHome", allow_interactive_auth)]
    fn remove_home(&self, user_name: String) -> zbus::Result<()>;
}
