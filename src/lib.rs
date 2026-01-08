//! Rust 🦀RBAC🦀 library with some crabby🦀🧙 macro magic! Not so blazingly fast yet, but has all 🚀🚀🚀 chances.
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
//!    let mut rbac_service = RbacService::new(None);
//!    rbac_service.add_role(Role {
//!        name: "OrderManager".to_string(),
//!        permissions: vec![
//!            "Orders::Order::*".to_string(),
//!            "Orders::OrderItem::*".to_string(),
//!            "Orders::Invoice::{Read,Generate}".to_string(),
//!        ],
//!    });
//!    
//!    rbac_service.add_role(Role {
//!        name: "Admin".to_string(),
//!        permissions: vec!["*".to_string()],
//!    });
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
//! }
//!
//! test_rbac();
//!
//!```
use std::fmt;
mod example;
mod r#macro;
mod registry;
#[cfg(test)]
mod tests;

pub use registry::RbacService;
use serde::{Deserialize, Serialize};


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
pub struct Role {
    pub name: String,
    pub permissions: Vec<String>,
}


