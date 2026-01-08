# RBACrab

Rust 🦀RBAC🦀 library with some crabby🦀🧙 macro magic! Not so blazingly fast yet, but has all 🚀🚀🚀 chances!

<p style="text-align: center;"><img src="img/rbacrab.png" alt="RBACrab" width="400"/></p>


Basic usage example:

```
use rbacrab::*;

define_permissions! {
    // Orders domain - manages orders, items, and invoices
    pub domain Orders {
        // Order operations
        Order {
            Read => "View orders",
            Create => "Create orders",
            Update => "Update orders",
            Cancel => "Cancel orders",
        },
        // Order item operations
        OrderItem {
            Read => "View order items",
            Add => "Add items to order",
            Remove => "Remove items from order",
        },
        // Invoice operations
        Invoice {
            Read => "View invoices",
            Generate => "Generate invoices",
            Send => "Send invoices to customers",
        },
    }
}

struct User {
    name: String,
    roles: Vec<String>,
}

impl RbacSubject for User {
    fn get_roles(&self) -> &Vec<String> {
        &self.roles
    }
    fn name(&self) -> &str {
        &self.name
    }
}

fn test_rbac() {
   let mut rbac_service = RbacService::new();
   rbac_service.add_role(Role {
       name: "OrderManager".to_string(),
       permissions: vec![
           "Orders::Order::*".to_string(),
           "Orders::OrderItem::*".to_string(),
           "Orders::Invoice::{Read,Generate}".to_string(),
       ],
   });
   
   rbac_service.add_role(Role {
       name: "Admin".to_string(),
       permissions: vec!["*".to_string()],
   });

   let user = User {
        name: "user".to_string(),
        roles: vec!["OrderManager".to_string()]
    };

   let admin = User {
        name: "admin".to_string(),
        roles: vec!["Admin".to_string()]
    };

   assert!(rbac_service.has_permission(&user, Orders::Order::Update).is_ok());
   assert!(rbac_service.has_permission(&user, Orders::Invoice::Send).is_err());
   assert!(rbac_service.has_permission(&admin, Orders::Invoice::Send).is_ok());
}

test_rbac();

```