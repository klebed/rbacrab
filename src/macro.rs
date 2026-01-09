/// Macro for generating module permission set with 3-level hierarchy: Domain::Object::Permission
/// 
/// Example usage:
/// ```
/// use rbacrab::define_permissions;
/// 
/// define_permissions! {
///     // Orders domain - manages orders, items, and invoices
///     pub domain Orders {
///         // Order operations
///         Order {
///             Read => "View orders",
///             Create => "Create orders",
///             Update => "Update orders",
///             Cancel => "Cancel orders",
///         },
///         // Order item operations
///         OrderItem {
///             Read => "View order items",
///             Add => "Add items to order",
///             Remove => "Remove items from order",
///         },
///         // Invoice operations
///         Invoice {
///             Read => "View invoices",
///             Generate => "Generate invoices",
///             Send => "Send invoices to customers",
///         },
///     }
/// }
/// ```
#[macro_export]
macro_rules! define_permissions {
    (
        $(#[$meta:meta])*
        $vis:vis domain $domain_mod:ident {
            $(
                $(#[$obj_meta:meta])*
                $object_type:ident {
                    $(
                        $(#[$action_meta:meta])*
                        $action:ident => $description:literal
                    ),* $(,)?
                }
            ),* $(,)?
        }
    ) => {
        $(#[$meta])*
        #[allow(non_snake_case)]
        $vis mod $domain_mod {

            // Object type enums
            $(
                $(#[$obj_meta])*
                #[derive(Debug, Clone, PartialEq, Eq, Hash)]
                pub enum $object_type {
                    $(
                        $(#[$action_meta])*
                        $action,
                    )*
                }

                impl $object_type {
                    pub fn description(&self) -> &'static str {
                        match self {
                            $(Self::$action => $description,)*
                        }
                    }

                    pub fn action(&self) -> &'static str {
                        match self {
                            $(Self::$action => stringify!($action),)*
                        }
                    }

                    #[allow(unused)]
                    pub fn object_type() -> &'static str {
                        stringify!($object_type)
                    }
                }

                impl std::fmt::Display for $object_type {
                    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                        write!(f, "{}::{}::{}", stringify!($domain_mod), stringify!($object_type), self.action())
                    }
                }

                impl $crate::Permission for $object_type {
                    fn domain() -> &'static str {
                        stringify!($domain_mod)
                    }

                    fn object_type(&self) -> &'static str {
                        stringify!($object_type)
                    }

                    fn action(&self) -> &'static str {
                        self.action()
                    }

                    fn from_string(s: &str) -> Option<Self> {
                        let parts: Vec<&str> = s.split("::").collect();
                        if parts.len() != 3 || parts[0] != stringify!($domain_mod) || parts[1] != stringify!($object_type) {
                            return None;
                        }
                        
                        match parts[2] {
                            $(stringify!($action) => Some(Self::$action),)*
                            _ => None,
                        }
                    }

                    fn all_permissions() -> Vec<Self> {
                        vec![$(Self::$action,)*]
                    }

                    fn description(&self) -> &'static str {
                        self.description()
                    }
                }
            )*

            // Helper function to register all permissions from this domain
            pub fn register_all(registry: &mut $crate::RbacServiceBuilder) {
                $(
                    registry.register_permissions::<$object_type>();
                )*
            }
        }
    };
}

