use crate::example::test::*;
use crate::*;

/// User with roles
#[derive(Debug, Clone)]
pub struct User {
    pub name: String,
    pub roles: Vec<String>,
}

impl RbacSubject for User {
    fn get_roles(&self) -> &Vec<String> {
        &self.roles
    }

    fn name(&self) -> &str {
        &self.name
    }
}

#[test]
fn test_clean_permission_syntax() {
    let rbac_service = setup_rbac();

    println!(
        "Full permission list: \n{:#?}",
        rbac_service
            .get_all_permissions()
            .iter()
            .map(|perm| { format!("{} => {}", perm.full_name, perm.description) })
            .collect::<Vec<String>>()
    );

    // User with UserManager role
    let mgmt_user = User {
        name: "mgmt".to_string(),
        roles: vec!["UserManager".to_string(), "TemplateCreator".to_string()],
    };

    // Clean syntax: Users::User::Create
    assert!(
        rbac_service
            .has_permission(&mgmt_user, Users::User::Create)
            .is_ok()
    );

    // Clean syntax: Users::Method::Read
    assert!(
        rbac_service
            .has_permission(&mgmt_user, Users::Method::Read)
            .is_ok()
    );

    // Clean syntax: Templates::Template::Create
    assert!(
        rbac_service
            .has_permission(&mgmt_user, Templates::Template::Create)
            .is_ok()
    );

    // Should NOT have Templates::Template::Delete
    assert!(
        rbac_service
            .has_permission(&mgmt_user, Templates::Template::Delete)
            .is_err()
    );

    // Clean syntax: Users::Notify::Write
    assert!(
        rbac_service
            .has_permission(&mgmt_user, Users::Notify::Write)
            .is_ok()
    );
}

#[test]
fn test_order_permissions() {
    let rbac_service = setup_rbac();

    let order_mgr = User {
        name: "order_manager".to_string(),
        roles: vec!["OrderManager".to_string()],
    };

    // Clean syntax throughout!
    assert!(
        rbac_service
            .has_permission(&order_mgr, Orders::Order::Create)
            .is_ok()
    );
    assert!(
        rbac_service
            .has_permission(&order_mgr, Orders::OrderItem::Add)
            .is_ok()
    );
    assert!(
        rbac_service
            .has_permission(&order_mgr, Orders::Invoice::Read)
            .is_ok()
    );
    assert!(
        rbac_service
            .has_permission(&order_mgr, Orders::Invoice::Generate)
            .is_ok()
    );

    // Should NOT have Orders::Invoice::Send
    assert!(
        rbac_service
            .has_permission(&order_mgr, Orders::Invoice::Send)
            .is_err()
    );
}

#[test]
fn test_admin_has_all() {
    let rbac_service = setup_rbac();

    let admin = User {
        name: "admin".to_string(),
        roles: vec!["Admin".to_string()],
    };

    // Admin should have everything
    assert!(
        rbac_service
            .has_permission(&admin, Users::User::Delete)
            .is_ok()
    );
    assert!(
        rbac_service
            .has_permission(&admin, Templates::Template::Delete)
            .is_ok()
    );
    assert!(
        rbac_service
            .has_permission(&admin, Orders::Invoice::Generate)
            .is_ok()
    );
}

#[test]
fn test_permission_string_format() {
    // Test the format is correct: Domain::ObjectType::Action
    assert_eq!(Users::User::Create.to_string(), "Users::User::Create");
    assert_eq!(
        Orders::Invoice::Generate.to_string(),
        "Orders::Invoice::Generate"
    );
    assert_eq!(
        Templates::Template::Read.to_string(),
        "Templates::Template::Read"
    );
}

#[test]
fn test_permission_registry() {
    let service = setup_rbac();

    // Check specific permission info
    let perm_info = service.get("Users::User::Create").unwrap();
    assert_eq!(perm_info.domain, "Users");
    assert_eq!(perm_info.object_type, "User");
    assert_eq!(perm_info.action, "Create");
    assert_eq!(perm_info.description, "Create new users");

    // Check Order domain permission
    let order_perm = service.get("Orders::Invoice::Generate").unwrap();
    assert_eq!(order_perm.domain, "Orders");
    assert_eq!(order_perm.object_type, "Invoice");
    assert_eq!(order_perm.action, "Generate");
}

#[test]
fn test_wildcard_patterns() {
    let rbac_service = setup_rbac();

    let user_mgr = User {
        name: "user_mgr".to_string(),
        roles: vec!["UserManager".to_string()],
    };

    // Users::User::* should grant all User object permissions
    assert!(
        rbac_service
            .has_permission(&user_mgr, Users::User::Read)
            .is_ok()
    );
    assert!(
        rbac_service
            .has_permission(&user_mgr, Users::User::Archive)
            .is_ok()
    );

    // But not Template domain permissions
    assert!(
        rbac_service
            .has_permission(&user_mgr, Templates::Template::Read)
            .is_err()
    );
}

#[test]
fn test_action_set_patterns() {
    let rbac_service = setup_rbac();

    let creator = User {
        name: "creator".to_string(),
        roles: vec!["TemplateCreator".to_string()],
    };

    // Should have Create and Write from the set
    assert!(
        rbac_service
            .has_permission(&creator, Templates::Template::Create)
            .is_ok()
    );
    assert!(
        rbac_service
            .has_permission(&creator, Templates::Template::Write)
            .is_ok()
    );

    // But not Read or Delete
    assert!(
        rbac_service
            .has_permission(&creator, Templates::Template::Read)
            .is_err()
    );
    assert!(
        rbac_service
            .has_permission(&creator, Templates::Template::Delete)
            .is_err()
    );
}

#[test]
fn test_update_roles() {
    let rbac_service = setup_rbac();

    let creator = User {
        name: "creator".to_string(),
        roles: vec!["TemplateCreator".to_string()],
    };

    assert!(
        rbac_service
            .has_permission(&creator, Templates::Template::Write)
            .is_ok()
    );

    let mut updater = rbac_service.updater_clean();
    updater.add_role(Role::new(
            "TemplateCreator",
            vec![
                "Templates::Template::{Create}".to_string(),
                "Users::Notify::Write".to_string(),
            ],
        ));

    updater.update(&rbac_service);

    assert!(
        rbac_service
            .has_permission(&creator, Templates::Template::Write)
            .is_err()
    );

    assert!(
        rbac_service
            .has_permission(&creator, Users::Notify::Write)
            .is_ok()
    );
}
