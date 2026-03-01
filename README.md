# RBACrab

Rust 🦀RBAC🦀 micro library with some crabby🦀🧙 macro magic! Blazingly 🚀🚀🚀 fast!

<p style="text-align: center;"><img src="img/rbacrab.png" alt="RBACrab" width="400"/></p>

Library intended to be lightweight and simple as possible. 

  Type-safe, zero-allocation RBAC for Rust. 2 dependencies. ~800 lines.                         
                                         
  ## Why RBACrab

  - **Compile-time permission safety.** The `define_permissions!` macro generates typed enums — `Orders::Invoice::Read`, not `"orders.invoice.read"`. Typos are caught by the compiler, not by a 3am production alert.
  - **Zero-allocation permission checks.** `has_permission()` does pure `&str` hash lookups. No `String` construction on the hot path. tens of nanoseconds per check.
  - **Roles are data, not code.** Roles are serializable (serde) — store them in a database, config file, or external service. Permissions are code. This separation means you can change who can do what without redeploying.
  - **Lock-free runtime updates.** Swap the entire role set atomically via `arc-swap`. Readers never block. Zero downtime role reloads.
  - **Composition over inheritance.** Users hold multiple roles — the permission check is a flat union. No inheritance chains, no diamond problem, no cascading side effects. The Rust way.
  - **Thread-safe by design.** `RbacService` is `Send + Sync`. Works in any async runtime.

  ## Permission Hierarchy

  Three levels: **Domain → Object → Action**

  ```
  Users::User::Read       — single permission
  Users::User::*          — all actions on User
  Users::*                — all objects and actions in Users domain
  *                       — everything
  ```

  Roles specify permissions as strings with wildcards and action sets:

  ```rust
  Role::new("OrderManager", vec![
      "Orders::Order::*".to_string(),                    // all Order actions
      "Orders::Invoice::{Read,Generate}".to_string(),    // specific Invoice actions
  ])
  ```


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
        "OrderManager",
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