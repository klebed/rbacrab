use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use rbacrab::*;

// =============================================================================
// Permission definitions — 5 domains, ~30 object types, 100+ permissions
// =============================================================================

define_permissions! {
    pub domain Users {
        User {
            Read => "View user information",
            Write => "Modify user information",
            Create => "Create new users",
            Delete => "Delete users",
            Lock => "Lock/unlock user accounts",
            Archive => "Archive user accounts",
        },
        Method {
            Read => "View authentication methods",
            Write => "Modify authentication methods",
            Delete => "Delete authentication methods",
            Activate => "Activate/deactivate methods",
        },
        Session {
            Read => "View active sessions",
            Revoke => "Revoke sessions",
        },
        Audit {
            Read => "View audit logs",
            Export => "Export audit data",
        },
    }
}

define_permissions! {
    pub domain Orders {
        Order {
            Read => "View orders",
            Create => "Create orders",
            Update => "Update orders",
            Cancel => "Cancel orders",
            Approve => "Approve orders",
        },
        OrderItem {
            Read => "View order items",
            Add => "Add items to order",
            Remove => "Remove items from order",
            Update => "Update item quantity",
        },
        Invoice {
            Read => "View invoices",
            Generate => "Generate invoices",
            Send => "Send invoices to customers",
            Void => "Void invoices",
        },
        Payment {
            Read => "View payments",
            Process => "Process payments",
            Refund => "Issue refunds",
        },
        Shipment {
            Read => "View shipments",
            Create => "Create shipments",
            Track => "Track shipments",
            Cancel => "Cancel shipments",
        },
    }
}

define_permissions! {
    pub domain Inventory {
        Product {
            Read => "View products",
            Create => "Create products",
            Update => "Update products",
            Delete => "Delete products",
            Import => "Bulk import products",
        },
        Category {
            Read => "View categories",
            Create => "Create categories",
            Update => "Update categories",
            Delete => "Delete categories",
        },
        Warehouse {
            Read => "View warehouses",
            Create => "Create warehouses",
            Update => "Update warehouses",
            Deactivate => "Deactivate warehouses",
        },
        StockMovement {
            Read => "View stock movements",
            Create => "Record stock movements",
            Approve => "Approve stock adjustments",
        },
    }
}

define_permissions! {
    pub domain Content {
        Article {
            Read => "View articles",
            Create => "Create articles",
            Update => "Update articles",
            Delete => "Delete articles",
            Publish => "Publish articles",
            Archive => "Archive articles",
        },
        Comment {
            Read => "View comments",
            Create => "Create comments",
            Delete => "Delete comments",
            Moderate => "Moderate comments",
        },
        Media {
            Read => "View media",
            Upload => "Upload media",
            Delete => "Delete media",
            Organize => "Organize media folders",
        },
        Tag {
            Read => "View tags",
            Create => "Create tags",
            Delete => "Delete tags",
        },
    }
}

define_permissions! {
    pub domain Analytics {
        Report {
            Read => "View reports",
            Create => "Create custom reports",
            Schedule => "Schedule reports",
        },
        Dashboard {
            Read => "View dashboards",
            Create => "Create dashboards",
            Share => "Share dashboards",
        },
        Export {
            Csv => "Export as CSV",
            Pdf => "Export as PDF",
            Api => "API data access",
        },
    }
}

// =============================================================================
// Test subject
// =============================================================================

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

// =============================================================================
// Fixture: build the full service with 10 roles
// =============================================================================

fn build_service() -> RbacService {
    let mut builder = RbacService::builder();

    builder.add_role(Role::new("Viewer", vec![
        "Users::User::Read".to_string(),
        "Users::Session::Read".to_string(),
        "Orders::Order::Read".to_string(),
        "Orders::OrderItem::Read".to_string(),
        "Orders::Invoice::Read".to_string(),
        "Orders::Payment::Read".to_string(),
        "Orders::Shipment::Read".to_string(),
        "Inventory::Product::Read".to_string(),
        "Inventory::Category::Read".to_string(),
        "Content::Article::Read".to_string(),
    ]));

    builder.add_role(Role::new("UserManager", vec![
        "Users::User::*".to_string(),
        "Users::Method::*".to_string(),
        "Users::Session::*".to_string(),
    ]));

    builder.add_role(Role::new("OrderClerk", vec![
        "Orders::Order::{Read,Create,Update}".to_string(),
        "Orders::OrderItem::{Read,Add,Remove,Update}".to_string(),
        "Orders::Invoice::{Read,Generate}".to_string(),
        "Orders::Payment::Read".to_string(),
        "Orders::Shipment::{Read,Track}".to_string(),
    ]));

    builder.add_role(Role::new("OrderManager", vec![
        "Orders::Order::*".to_string(),
        "Orders::OrderItem::*".to_string(),
        "Orders::Invoice::*".to_string(),
        "Orders::Payment::*".to_string(),
        "Orders::Shipment::*".to_string(),
    ]));

    builder.add_role(Role::new("InventoryManager", vec![
        "Inventory::*".to_string(),
    ]));

    builder.add_role(Role::new("ContentEditor", vec![
        "Content::Article::{Read,Create,Update}".to_string(),
        "Content::Comment::{Read,Create}".to_string(),
        "Content::Media::{Read,Upload}".to_string(),
        "Content::Tag::{Read,Create}".to_string(),
    ]));

    builder.add_role(Role::new("ContentAdmin", vec![
        "Content::*".to_string(),
    ]));

    builder.add_role(Role::new("Analyst", vec![
        "Analytics::Report::{Read,Create}".to_string(),
        "Analytics::Dashboard::{Read,Create}".to_string(),
        "Analytics::Export::{Csv,Pdf}".to_string(),
    ]));

    builder.add_role(Role::new("SuperAdmin", vec![
        "*".to_string(),
    ]));

    builder.add_role(Role::new("ComplexRole", vec![
        "Users::User::{Read,Write,Create}".to_string(),
        "Users::Method::{Read,Activate}".to_string(),
        "Users::Session::Read".to_string(),
        "Users::Audit::{Read,Export}".to_string(),
        "Orders::Order::{Read,Create,Update}".to_string(),
        "Orders::OrderItem::*".to_string(),
        "Orders::Invoice::{Read,Generate,Send}".to_string(),
        "Orders::Payment::{Read,Process}".to_string(),
        "Orders::Shipment::{Read,Create,Track}".to_string(),
        "Inventory::Product::{Read,Create,Update}".to_string(),
        "Inventory::Category::Read".to_string(),
        "Inventory::Warehouse::Read".to_string(),
        "Inventory::StockMovement::Read".to_string(),
        "Content::Article::{Read,Create,Update,Publish}".to_string(),
        "Content::Comment::{Read,Create,Moderate}".to_string(),
        "Content::Media::{Read,Upload,Organize}".to_string(),
        "Content::Tag::*".to_string(),
        "Analytics::Report::Read".to_string(),
        "Analytics::Dashboard::Read".to_string(),
    ]));

    builder.build()
}

// =============================================================================
// Permission strings for role compilation benchmarks
// =============================================================================

fn few_permissions() -> Vec<String> {
    vec![
        "Users::User::Read".to_string(),
        "Users::User::Write".to_string(),
        "Orders::Order::Read".to_string(),
        "Inventory::Product::Read".to_string(),
        "Content::Article::Read".to_string(),
    ]
}

fn medium_permissions() -> Vec<String> {
    vec![
        "Users::User::*".to_string(),
        "Users::Method::{Read,Activate}".to_string(),
        "Orders::Order::{Read,Create,Update}".to_string(),
        "Orders::OrderItem::*".to_string(),
        "Orders::Invoice::{Read,Generate,Send}".to_string(),
        "Orders::Payment::Read".to_string(),
        "Inventory::Product::{Read,Create,Update}".to_string(),
        "Inventory::Category::Read".to_string(),
        "Content::Article::{Read,Create,Update}".to_string(),
        "Content::Comment::Read".to_string(),
        "Content::Media::{Read,Upload}".to_string(),
        "Content::Tag::Read".to_string(),
        "Analytics::Report::Read".to_string(),
        "Analytics::Dashboard::Read".to_string(),
        "Analytics::Export::Csv".to_string(),
    ]
}

fn many_permissions() -> Vec<String> {
    vec![
        "Users::User::{Read,Write,Create}".to_string(),
        "Users::Method::{Read,Write,Activate}".to_string(),
        "Users::Session::{Read,Revoke}".to_string(),
        "Users::Audit::{Read,Export}".to_string(),
        "Orders::Order::{Read,Create,Update,Cancel,Approve}".to_string(),
        "Orders::OrderItem::{Read,Add,Remove,Update}".to_string(),
        "Orders::Invoice::{Read,Generate,Send,Void}".to_string(),
        "Orders::Payment::{Read,Process,Refund}".to_string(),
        "Orders::Shipment::{Read,Create,Track,Cancel}".to_string(),
        "Inventory::Product::{Read,Create,Update,Delete,Import}".to_string(),
        "Inventory::Category::{Read,Create,Update,Delete}".to_string(),
        "Inventory::Warehouse::{Read,Create,Update,Deactivate}".to_string(),
        "Inventory::StockMovement::{Read,Create,Approve}".to_string(),
        "Content::Article::{Read,Create,Update,Delete,Publish,Archive}".to_string(),
        "Content::Comment::{Read,Create,Delete,Moderate}".to_string(),
        "Content::Media::{Read,Upload,Delete,Organize}".to_string(),
        "Content::Tag::{Read,Create,Delete}".to_string(),
        "Analytics::Report::{Read,Create,Schedule}".to_string(),
        "Analytics::Dashboard::{Read,Create,Share}".to_string(),
        "Analytics::Export::{Csv,Pdf,Api}".to_string(),
    ]
}

// =============================================================================
// 1. Role compilation benchmarks
// =============================================================================

fn bench_role_compilation(c: &mut Criterion) {
    let mut group = c.benchmark_group("role_compilation");

    group.bench_function("few_permissions_5", |b| {
        let perms = few_permissions();
        b.iter(|| Role::new(black_box("TestRole"), black_box(perms.clone())))
    });

    group.bench_function("medium_permissions_15", |b| {
        let perms = medium_permissions();
        b.iter(|| Role::new(black_box("TestRole"), black_box(perms.clone())))
    });

    group.bench_function("many_permissions_20", |b| {
        let perms = many_permissions();
        b.iter(|| Role::new(black_box("TestRole"), black_box(perms.clone())))
    });

    group.bench_function("global_wildcard", |b| {
        b.iter(|| Role::new(black_box("Admin"), black_box(vec!["*".to_string()])))
    });

    group.finish();
}

// =============================================================================
// 2. Permission check by match type
// =============================================================================

fn bench_permission_check_by_match_type(c: &mut Criterion) {
    let service = build_service();
    let mut group = c.benchmark_group("permission_check_by_match_type");

    // Global wildcard — fastest path
    let superadmin = User {
        name: "superadmin".into(),
        roles: vec!["SuperAdmin".into()],
    };
    group.bench_function("global_wildcard_hit", |b| {
        b.iter(|| service.has_permission(black_box(&superadmin), black_box(Inventory::Product::Delete)))
    });

    // Domain wildcard
    let inv_manager = User {
        name: "inv_manager".into(),
        roles: vec!["InventoryManager".into()],
    };
    group.bench_function("domain_wildcard_hit", |b| {
        b.iter(|| service.has_permission(black_box(&inv_manager), black_box(Inventory::StockMovement::Approve)))
    });

    // Object wildcard
    let user_manager = User {
        name: "user_manager".into(),
        roles: vec!["UserManager".into()],
    };
    group.bench_function("object_wildcard_hit", |b| {
        b.iter(|| service.has_permission(black_box(&user_manager), black_box(Users::User::Archive)))
    });

    // Exact match (expanded from action set)
    let content_editor = User {
        name: "content_editor".into(),
        roles: vec!["ContentEditor".into()],
    };
    group.bench_function("exact_match_hit", |b| {
        b.iter(|| service.has_permission(black_box(&content_editor), black_box(Content::Article::Update)))
    });

    // Permission denied — miss all 4 layers (worst case)
    let viewer = User {
        name: "viewer".into(),
        roles: vec!["Viewer".into()],
    };
    group.bench_function("permission_denied", |b| {
        b.iter(|| service.has_permission(black_box(&viewer), black_box(Users::User::Delete)))
    });

    group.finish();
}

// =============================================================================
// 3. Permission check by role count
// =============================================================================

fn bench_permission_check_by_role_count(c: &mut Criterion) {
    let service = build_service();
    let mut group = c.benchmark_group("permission_check_by_role_count");

    // 1 role — direct hit
    let user_1role = User {
        name: "user1".into(),
        roles: vec!["OrderClerk".into()],
    };
    group.bench_function("1_role_hit", |b| {
        b.iter(|| service.has_permission(black_box(&user_1role), black_box(Orders::Order::Create)))
    });

    // 3 roles — permission found in last role
    let user_3roles = User {
        name: "user3".into(),
        roles: vec!["Viewer".into(), "ContentEditor".into(), "Analyst".into()],
    };
    group.bench_function("3_roles_hit_last", |b| {
        b.iter(|| service.has_permission(black_box(&user_3roles), black_box(Analytics::Export::Csv)))
    });

    // 5 roles — permission denied, scan all
    let user_5roles = User {
        name: "user5".into(),
        roles: vec![
            "Viewer".into(),
            "ContentEditor".into(),
            "Analyst".into(),
            "OrderClerk".into(),
            "UserManager".into(),
        ],
    };
    group.bench_function("5_roles_denied", |b| {
        b.iter(|| service.has_permission(black_box(&user_5roles), black_box(Inventory::Product::Delete)))
    });

    group.finish();
}

// =============================================================================
// 4. Permission check at scale — throughput
// =============================================================================

fn bench_permission_check_at_scale(c: &mut Criterion) {
    let service = build_service();
    let mut group = c.benchmark_group("permission_check_at_scale");

    let complex_user = User {
        name: "complex".into(),
        roles: vec!["ComplexRole".into()],
    };

    // 100 mixed checks — simulating a request handler
    group.bench_function("100_mixed_checks", |b| {
        b.iter(|| {
            // Granted checks (various match types)
            for _ in 0..10 {
                let _ = service.has_permission(black_box(&complex_user), black_box(Users::User::Read));
                let _ = service.has_permission(black_box(&complex_user), black_box(Orders::OrderItem::Add));
                let _ = service.has_permission(black_box(&complex_user), black_box(Content::Tag::Read));
                let _ = service.has_permission(black_box(&complex_user), black_box(Analytics::Report::Read));
                let _ = service.has_permission(black_box(&complex_user), black_box(Orders::Invoice::Send));
                // Denied checks
                let _ = service.has_permission(black_box(&complex_user), black_box(Users::User::Delete));
                let _ = service.has_permission(black_box(&complex_user), black_box(Orders::Order::Approve));
                let _ = service.has_permission(black_box(&complex_user), black_box(Inventory::Product::Delete));
                let _ = service.has_permission(black_box(&complex_user), black_box(Content::Article::Delete));
                let _ = service.has_permission(black_box(&complex_user), black_box(Analytics::Export::Api));
            }
        })
    });

    group.finish();
}

// =============================================================================
// 5. Runtime role update
// =============================================================================

fn bench_runtime_role_update(c: &mut Criterion) {
    let mut group = c.benchmark_group("runtime_role_update");

    // Clean updater: build 10 roles from scratch and swap
    group.bench_function("clean_update_10_roles", |b| {
        let service = build_service();
        b.iter(|| {
            let mut updater = service.updater_clean();
            updater.add_role(Role::new("Viewer", few_permissions()));
            updater.add_role(Role::new("UserManager", vec!["Users::User::*".into(), "Users::Method::*".into()]));
            updater.add_role(Role::new("OrderClerk", vec!["Orders::Order::{Read,Create,Update}".into()]));
            updater.add_role(Role::new("OrderManager", vec!["Orders::*".into()]));
            updater.add_role(Role::new("InventoryManager", vec!["Inventory::*".into()]));
            updater.add_role(Role::new("ContentEditor", vec!["Content::Article::{Read,Create,Update}".into()]));
            updater.add_role(Role::new("ContentAdmin", vec!["Content::*".into()]));
            updater.add_role(Role::new("Analyst", vec!["Analytics::Report::Read".into()]));
            updater.add_role(Role::new("SuperAdmin", vec!["*".into()]));
            updater.add_role(Role::new("ComplexRole", many_permissions()));
            updater.update(black_box(&service));
        })
    });

    // Copy updater: modify 1 role and swap
    group.bench_function("copy_update_1_role", |b| {
        let service = build_service();
        b.iter(|| {
            let mut updater = service.updater_copy();
            updater.add_role(Role::new("Viewer", medium_permissions()));
            updater.update(black_box(&service));
        })
    });

    group.finish();
}

// =============================================================================
// 6. Role deserialization (serde)
// =============================================================================

fn bench_role_deserialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("role_deserialization");

    let small_json = serde_json::to_string(&Role::new("SmallRole", few_permissions())).unwrap();
    let large_json = serde_json::to_string(&Role::new("LargeRole", many_permissions())).unwrap();

    group.bench_function("small_role_5_perms", |b| {
        b.iter(|| serde_json::from_str::<Role>(black_box(&small_json)).unwrap())
    });

    group.bench_function("large_role_20_perms", |b| {
        b.iter(|| serde_json::from_str::<Role>(black_box(&large_json)).unwrap())
    });

    group.finish();
}

// =============================================================================
// Criterion groups
// =============================================================================

criterion_group!(
    benches,
    bench_role_compilation,
    bench_permission_check_by_match_type,
    bench_permission_check_by_role_count,
    bench_permission_check_at_scale,
    bench_runtime_role_update,
    bench_role_deserialization,
);
criterion_main!(benches);
