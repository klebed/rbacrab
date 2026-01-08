// ============================================================================
// Domain Adapters - Example Usage with clean 3-level hierarchy
// ============================================================================
#[cfg(test)]
pub mod test {
    #[cfg(test)]
    use crate::RbacSubject;
    use crate::{RbacError, RbacService, Role, define_permissions};

    // Users domain with multiple object types
    define_permissions! {
        /// Users domain - manages users, authentication methods, and notifications

        pub(crate) domain Users {
            /// User account operations
            User {
                Read => "View user information",
                Write => "Modify user information",
                Create => "Create new users",
                Delete => "Delete users",
                Lock => "Lock/unlock user accounts",
                Archive => "Archive user accounts",
            },
            /// Authentication method operations
            Method {
                Read => "View authentication methods",
                Write => "Modify authentication methods",
                Delete => "Delete authentication methods",
                Activate => "Activate/deactivate methods",
            },
            /// Notification operations
            Notify {
                Write => "Send notifications",
            },
        }
    }

    // Templates domain
    define_permissions! {
        /// Templates domain - manages document templates
        pub domain Templates {
            /// Template operations
            Template {
                Read => "View templates",
                Write => "Modify templates",
                Create => "Create new templates",
                Delete => "Delete templates",
            },
        }
    }

    // Orders domain with multiple object types
    define_permissions! {
        /// Orders domain - manages orders, items, and invoices
        pub domain Orders {
            /// Order operations
            Order {
                Read => "View orders",
                Create => "Create orders",
                Update => "Update orders",
                Cancel => "Cancel orders",
            },
            /// Order item operations
            OrderItem {
                Read => "View order items",
                Add => "Add items to order",
                Remove => "Remove items from order",
            },
            /// Invoice operations
            Invoice {
                Read => "View invoices",
                Generate => "Generate invoices",
                Send => "Send invoices to customers",
            },
        }
    }

    pub fn setup_rbac() -> RbacService {
        // Setup roles (normally loaded from DB)
        let mut service = RbacService::new(None);

        // Register all permissions (just in case we need full list)
        Users::register_all(&mut service);
        Templates::register_all(&mut service);
        Orders::register_all(&mut service);

        service.add_role(Role {
            name: "UserManager".to_string(),
            permissions: vec!["Users::User::*".to_string(), "Users::Method::*".to_string()],
        });

        service.add_role(Role {
            name: "TemplateCreator".to_string(),
            permissions: vec![
                "Templates::Template::{Create,Write}".to_string(),
                "Users::Notify::Write".to_string(),
            ],
        });

        service.add_role(Role {
            name: "OrderManager".to_string(),
            permissions: vec![
                "Orders::Order::*".to_string(),
                "Orders::OrderItem::*".to_string(),
                "Orders::Invoice::{Read,Generate}".to_string(),
            ],
        });

        service.add_role(Role {
            name: "Admin".to_string(),
            permissions: vec!["*".to_string()],
        });

        service
    }

    #[allow(unused)]
    pub fn example_user_service(
        user: &impl RbacSubject,
        checker: &RbacService,
    ) -> Result<(), RbacError> {
        // Check Users::User::Create permission
        checker.has_permission(user, Users::User::Create)?;

        println!("User {} can create users", user.name());
        Ok(())
    }

    #[allow(unused)]
    pub fn example_template_service(
        user: &impl RbacSubject,
        checker: &RbacService,
    ) -> Result<(), RbacError> {
        // Check Templates::Template::Write permission
        checker.has_permission(user, Templates::Template::Write)?;

        println!("User {} can write templates", user.name());
        Ok(())
    }

    #[allow(unused)]
    pub fn example_order_service(
        user: &impl RbacSubject,
        checker: &RbacService,
    ) -> Result<(), RbacError> {
        // Check Orders::Order::Create permission
        checker.has_permission(user, Orders::Order::Create)?;

        // Check Orders::Invoice::Generate permission
        checker.has_permission(user, Orders::Invoice::Generate)?;

        println!(
            "User {} can create orders and generate invoices",
            user.name()
        );
        Ok(())
    }

    #[cfg(test)]
    #[allow(unused)]
    pub fn example_notification_service(
        user: &impl RbacSubject,
        checker: &RbacService,
    ) -> Result<(), RbacError> {
        // Check Users::Notify::Write permission
        checker.has_permission(user, Users::Notify::Write)?;

        println!("User {} can send notifications", user.name());
        Ok(())
    }
}
