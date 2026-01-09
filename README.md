# RBACrab

Rust 🦀RBAC🦀 micro library with some crabby🦀🧙 macro magic! Not so blazingly fast yet, but has all 🚀🚀🚀 chances!

<p style="text-align: center;"><img src="img/rbacrab.png" alt="RBACrab" width="400"/></p>

Library intended to be lightweight and simple as possible. 

Role is serializable and deserializable, so library user may store it anywhere (config files, DB, external service).
When role created or deserialized it compiles with several layers of sets, starting from global wildcard permission (all domains, all objects, all actions permitted)

Permission check require statically typed variant created by convenient macro define_permissions! or implemented Permission trait.

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
   let rbac_service = RbacService::builder()
   .add_role(Role::new(
       "OrderManager",
       vec![
           "Orders::Order::*".to_string(),
           "Orders::OrderItem::*".to_string(),
           "Orders::Invoice::{Read,Generate}".to_string(),
       ],
   ))
   .add_role(Role::new(
       "Admin",
       vec!["*".to_string()],
   ))
    .build();

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

    // Runtime update RBAC service roles with new set of roles:
    
    // Get clean updater (in case if old roles needed, use .updater_copy())
    let mut updater = rbac_service.updater_clean();
 
    updater.add_role(Role::new(
        "OrderManager".to_string(),
        vec![
            "Orders::Order::*".to_string(),
            "Orders::OrderItem::*".to_string(),
            "Orders::Invoice::{Read,Generate,Send}".to_string(),
        ],
    ));
 
    // Swap roles inside service (atomicly)
    updater.update(&rbac_service);
 
    assert!(rbac_service.has_permission(&user, Orders::Invoice::Send).is_ok());

}

test_rbac();

```