//! Rust 🦀RBAC🦀 library with some crabby🦀🧙 macro magic! Not so blazingly fast yet, but has all 🚀🚀🚀 chances.
//!
//! Library intended to be lightweight and simple as possible. 
//! 
//! Role is serializable and deserializable, so library user may store it anywhere (config files, DB, external service).
//! When role created or deserialized it compiles with several layers of sets, starting from global wildcard permission (all domains, all objects, all actions permitted)
//! 
//! Permission check require statically typed variant created by convenient macro [define_permissions!] or implemented [Permission] trait.
//! 
//! Example usage:
//!```
//! use rbacrab::*;
//!
//! define_permissions! {
//!     // Orders domain - manages orders, items, and invoices
//!     pub domain Orders {
//!         // Order operations
//!         Order {
//!             Read => "View orders",
//!             Create => "Create orders",
//!             Update => "Update orders",
//!             Cancel => "Cancel orders",
//!         },
//!         // Order item operations
//!         OrderItem {
//!             Read => "View order items",
//!             Add => "Add items to order",
//!             Remove => "Remove items from order",
//!         },
//!         // Invoice operations
//!         Invoice {
//!             Read => "View invoices",
//!             Generate => "Generate invoices",
//!             Send => "Send invoices to customers",
//!         },
//!     }
//! }
//!
//! struct User {
//!     name: String,
//!     roles: Vec<String>,
//! }
//!
//! impl RbacSubject for User {
//!     fn get_roles(&self) -> &Vec<String> {
//!         &self.roles
//!     }
//!     fn name(&self) -> &str {
//!         &self.name
//!     }
//! }
//!
//! fn test_rbac() {
//!    let mut rbac_service_builder = RbacService::builder();
//!
//!    // (optional) Register domain permission sets in RBAC service to collect full list.
//!    Orders::register_all(&mut rbac_service_builder);
//!
//!    rbac_service_builder.add_role(Role::new(
//!        "OrderManager",
//!        vec![
//!            "Orders::Order::*".to_string(),
//!            "Orders::OrderItem::*".to_string(),
//!            "Orders::Invoice::{Read,Generate}".to_string(),
//!        ],
//!    ));
//!    
//!    rbac_service_builder.add_role(Role::new(
//!        "Admin",
//!        vec!["*".to_string()],
//!    ));
//!
//!    let rbac_service = rbac_service_builder.build();
//!
//!    let user = User {
//!         name: "user".to_string(),
//!         roles: vec!["OrderManager".to_string()]
//!     };
//!
//!    let admin = User {
//!         name: "admin".to_string(),
//!         roles: vec!["Admin".to_string()]
//!     };
//!
//!    assert!(rbac_service.has_permission(&user, Orders::Order::Update).is_ok());
//!    assert!(rbac_service.has_permission(&user, Orders::Invoice::Send).is_err());
//!    assert!(rbac_service.has_permission(&admin, Orders::Invoice::Send).is_ok());
//!
//!    // Runtime update RBAC service roles with new set of roles:
//!    
//!    // Get clean updater (in case if old roles needed, use .updater_copy())
//!    let mut updater = rbac_service.updater_clean();
//!
//!    updater.add_role(Role::new(
//!        "OrderManager",
//!        vec![
//!            "Orders::Order::*".to_string(),
//!            "Orders::OrderItem::*".to_string(),
//!            "Orders::Invoice::{Read,Generate,Send}".to_string(),
//!        ],
//!    ));
//!
//!    // Swap roles inside service (atomicly)
//!    updater.update(&rbac_service);
//!
//!    assert!(rbac_service.has_permission(&user, Orders::Invoice::Send).is_ok());
//!
//! }
//!
//! test_rbac();
//!
//!```
use std::{
    collections::{HashSet},
    fmt,
};
mod example;
mod r#macro;
mod service;
#[cfg(test)]
mod tests;

use serde::{Deserialize, Serialize};
pub use service::{RbacService, RbacServiceBuilder, RbacServiceUpdater};

/// Trait that all permission enums must implement
pub trait Permission:
    Sized + fmt::Display + fmt::Debug + Clone + PartialEq + Eq + std::hash::Hash
{
    /// Returns the domain name (e.g., "Users", "Templates")
    fn domain() -> &'static str;

    /// Returns the object type (e.g., "User", "Method", "Template")
    fn object_type(&self) -> &'static str;

    /// Returns the action name (e.g., "Read", "Write")
    fn action(&self) -> &'static str;

    /// Returns full permission string (e.g., "Users::User::Read")
    fn to_permission_string(&self) -> String {
        format!(
            "{}::{}::{}",
            Self::domain(),
            self.object_type(),
            self.action()
        )
    }

    /// Parse from string representation
    fn from_string(s: &str) -> Option<Self>;

    /// Get all possible permissions for this resource
    fn all_permissions() -> Vec<Self>;

    /// Get human-readable description
    fn description(&self) -> &'static str;
}

/// Trait that any of the subjects (like User or Client) must implement to check permissions
pub trait RbacSubject {
    fn get_roles(&self) -> &Vec<String>;
    fn name(&self) -> &str;
}

#[derive(Debug, Clone, PartialEq)]
pub enum RbacError {
    PermissionDenied(String),
}

impl fmt::Display for RbacError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::PermissionDenied(p) => write!(f, "Permission denied: {}", p),
        }
    }
}

impl std::error::Error for RbacError {}

#[derive(Debug, Clone)]
pub struct PermissionInfo {
    pub domain: String,
    pub object_type: String,
    pub action: String,
    pub full_name: String,
    pub description: String,
}

/// Role definition with permissions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleS {
    pub name: String,
    pub permissions: Vec<String>,
}

impl From<Role> for RoleS {
    fn from(value: Role) -> Self {
        RoleS {
            name: value.name,
            permissions: value.permissions,
        }
    }
}

impl From<RoleS> for Role {
    fn from(value: RoleS) -> Self {
        Role::new(&value.name, value.permissions)
    }
}

/// Role definition with permissions
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(from = "RoleS")]
#[serde(into = "RoleS")]
pub struct Role {
    pub name: String,
    pub permissions: Vec<String>,
    pub compiled_permissions: CompiledPermissions,
}

impl Role {
    pub fn new(name: &str, permissions: Vec<String>) -> Self {
        Role {
            name: name.to_string(),
            compiled_permissions: CompiledPermissions::compile(&permissions),
            permissions,
        }
    }
}


#[derive(Debug, Default, Clone)]
pub struct CompiledPermissions {
    global_permission: bool,
    domain_wildcards: HashSet<String>,
    // Domain::Object
    object_wildcards: HashSet<(String, String)>,
    exact_permissions: HashSet<String>,
}

impl CompiledPermissions {
    pub fn compile(permissions: &Vec<String>) -> Self {
        let mut compiled = CompiledPermissions::default();
        
        for perm in permissions {
            // Check for global wildcard
            if perm == "*" {
                // Global wildcard covers everything - no need to process anything else
                return CompiledPermissions {
                    global_permission: true,
                    ..Default::default()
                };
            }
            
            let parts: Vec<&str> = perm.split("::").collect();
            
            match parts.len() {
                2 if parts[1] == "*" => {
                    // Domain wildcard: "Users::*"
                    let domain = parts[0].to_string();
                    compiled.domain_wildcards.insert(domain.clone());
                    
                    // Remove any object wildcards or exact permissions for this domain
                    compiled.object_wildcards.retain(|(d, _)| d != &domain);
                    compiled.exact_permissions.retain(|p| !p.starts_with(&format!("{}::", domain)));
                }
                3 if parts[2] == "*" => {
                    // Object wildcard: "Users::User::*"
                    let domain = parts[0].to_string();
                    let object = parts[1].to_string();
                    
                    // Only add if there's no domain wildcard covering this
                    if !compiled.domain_wildcards.contains(&domain) {
                        compiled.object_wildcards.insert((domain.clone(), object.clone()));
                        
                        // Remove any exact permissions for this domain::object
                        let prefix = format!("{}::{}::", domain, object);
                        compiled.exact_permissions.retain(|p| !p.starts_with(&prefix));
                    }
                }
                3 if parts[2].starts_with('{') && parts[2].ends_with('}') => {
                    // Action set: "Users::User::{Create,Write}"
                    let domain = parts[0].to_string();
                    let object = parts[1].to_string();
                    
                    // Only process if not covered by domain or object wildcard
                    if !compiled.domain_wildcards.contains(&domain) 
                        && !compiled.object_wildcards.contains(&(domain.clone(), object.clone())) {
                        
                        let actions_str = &parts[2][1..parts[2].len() - 1];
                        let actions: Vec<&str> = actions_str.split(',').map(|s| s.trim()).collect();
                        
                        // Expand action set into exact permissions
                        for action in actions {
                            let exact_perm = format!("{}::{}::{}", domain, object, action);
                            compiled.exact_permissions.insert(exact_perm);
                        }
                    }
                }
                _ => {
                    // Exact permission
                    if parts.len() == 3 {
                        let domain = parts[0].to_string();
                        let object = parts[1].to_string();
                        
                        // Only add if not covered by domain or object wildcard
                        if !compiled.domain_wildcards.contains(&domain) 
                            && !compiled.object_wildcards.contains(&(domain, object)) {
                            compiled.exact_permissions.insert(perm.to_owned());
                        }
                    } else {
                        // Invalid format, but add as exact match anyway
                        compiled.exact_permissions.insert(perm.to_owned());
                    }
                }
            }
        }
        
        compiled
    }
    
    /// Check if permission matches - O(1) with no allocations
    #[inline]
    pub fn matches(
        &self,
        perm_str: &str,
        domain: &str,
        object_type: &str,
    ) -> bool {
        // 1. Global wildcard check
        if self.global_permission {
            return true;
        }
        
        // 2. Domain wildcard hash lookup
        if self.domain_wildcards.contains(domain) {
            return true;
        }
        
        // 3. Object wildcard hash lookup
        if self.object_wildcards.contains(&(domain.to_string(), object_type.to_string())) {
            return true;
        }
        
        // 4. Exact match hash lookup
        if self.exact_permissions.contains(perm_str) {
            return true;
        }
        
        false
    }
}
