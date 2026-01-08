use std::collections::{BTreeMap, HashMap, HashSet};

use crate::{Permission, PermissionInfo, RbacError, RbacSubject, Role};

/// Main RBAC checker
pub struct RbacService {
    roles: HashMap<String, Role>,
    fallback_roles: Vec<String>,
    all_permissions: BTreeMap<String, PermissionInfo>,
}
impl RbacService {
    pub fn new(fallback_roles: Option<Vec<String>>) -> Self {
        Self {
            roles: HashMap::new(),
            fallback_roles: match fallback_roles {
                Some(roles) => roles,
                None => vec!["Default".to_string()],
            },
            all_permissions: BTreeMap::new(),
        }
    }

    pub fn add_role(&mut self, role: Role) {
        self.roles.insert(role.name.clone(), role);
    }

    pub fn load_roles(&mut self, roles: Vec<Role>) {
        for role in roles {
            self.add_role(role);
        }
    }

    /// Check if user has a specific permission
    pub fn has_permission<P: Permission>(
        &self,
        user: &impl RbacSubject,
        permission: P,
    ) -> Result<(), RbacError> {
        let perm_str = permission.to_permission_string();
        let domain = P::domain();
        let object_type = permission.object_type();
        let user_roles = user.get_roles();
        let user_roles = if user_roles.is_empty() {
            &self.fallback_roles
        } else {
            user_roles
        };

        // Collect all permissions from user's roles
        for role_name in user_roles {
            let role = match self.roles.get(role_name) {
                Some(role) => role,
                None => continue,
            };

            for perm_pattern in &role.permissions {
                if self.matches_pattern(&perm_str, perm_pattern, domain, object_type) {
                    return Ok(());
                }
            }
        }

        Err(RbacError::PermissionDenied(perm_str))
    }

    fn matches_pattern(&self, perm: &str, pattern: &str, domain: &str, object_type: &str) -> bool {
        // Handle global wildcard: "*"
        if pattern == "*" {
            return true;
        }

        // Handle domain-level wildcards: "Users::*"
        if pattern == format!("{}::*", domain) {
            return perm.starts_with(&format!("{}::", domain));
        }

        // Handle object-level wildcards: "Users::User::*"
        if pattern == format!("{}::{}::*", domain, object_type) {
            return perm.starts_with(&format!("{}::{}::", domain, object_type));
        }

        // Handle action sets: "Users::User::{Create,Write}"
        if pattern.contains('{') && pattern.contains('}') {
            let parts: Vec<&str> = pattern.split("::").collect();
            if parts.len() == 3 {
                let pat_domain = parts[0];
                let pat_object = parts[1];
                let actions_str = parts[2].trim_matches(|c| c == '{' || c == '}');

                if pat_domain == domain && pat_object == object_type {
                    let allowed_actions: HashSet<_> =
                        actions_str.split(',').map(|s| s.trim()).collect();

                    let perm_parts: Vec<&str> = perm.split("::").collect();
                    if perm_parts.len() == 3 {
                        return allowed_actions.contains(perm_parts[2]);
                    }
                }
            }
        }

        // Exact match
        perm == pattern
    }

    pub fn register<P: Permission>(&mut self) {
        for perm in P::all_permissions() {
            let info = PermissionInfo {
                domain: P::domain().to_string(),
                object_type: perm.object_type().to_string(),
                action: perm.action().to_string(),
                full_name: perm.to_permission_string(),
                description: perm.description().to_string(),
            };
            self.all_permissions.insert(info.full_name.clone(), info);
        }
    }

    pub fn get_all_permissions(&self) -> Vec<&PermissionInfo> {
        self.all_permissions.values().collect()
    }

    pub fn get(&self, perm: &str) -> Option<&PermissionInfo> {
        self.all_permissions.get(perm)
    }
}
