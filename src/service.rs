use std::{collections::{BTreeMap, HashMap, HashSet}, sync::Arc};

use arc_swap::{ArcSwap};

use crate::{Permission, PermissionInfo, RbacError, RbacSubject, Role};

/// RbacService - RBAC service that may be used to check if particular subject has particular permission by calling [.has_permission()][RbacService#method.has_permission].
pub struct RbacService {
    roles: ArcSwap<HashMap<String, Role>>,
    fallback_roles: Vec<String>,
    all_permissions: BTreeMap<String, PermissionInfo>,
}

/// RbacServiceBuilder - used when you create RBAC service. 
/// On this stage you may also register all possible permissions to create comprehensive list by calling [.get_all_permissions()][RbacService#method.get_all_permissions] on RbacService.
pub struct RbacServiceBuilder {
    roles: HashMap<String, Role>,
    fallback_roles: Option<Vec<String>>,
    all_permissions: BTreeMap<String, PermissionInfo>,
}

impl RbacServiceBuilder {

    pub fn build(&self) -> RbacService {
        RbacService {
            roles: ArcSwap::new( Arc::new(self.roles.clone())),
            fallback_roles: match &self.fallback_roles {
                Some(roles) => roles.clone(),
                None => vec!["Default".to_string()],
            },
            all_permissions: self.all_permissions.clone(),
        }
    }

    pub fn add_role(&mut self, role: Role) -> &mut Self {
        self.roles.insert(role.name.clone(), role);
        self
    }

    pub fn load_roles(&mut self, roles: Vec<Role>) -> &mut Self {
        for role in roles {
            self.add_role(role);
        }
        self
    }

    pub fn set_fallback_roles(&mut self, fallback_roles: Vec<String>) -> &mut Self {
        self.fallback_roles = Some(fallback_roles);
        self
    }

    pub fn register_permissions<P: Permission>(&mut self) {
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
}

pub struct RbacServiceUpdater {
    roles: HashMap<String, Role>,
    fallback_roles: Option<Vec<String>>,
}

impl RbacServiceUpdater {
    /// Adds one Role to map
    pub fn add_role(&mut self, role: Role) -> &mut Self {
        self.roles.insert(role.name.clone(), role);
        self
    }

    pub fn remove_role(&mut self, role_name: &str) -> &mut Self {
        self.roles.remove(role_name);
        self
    }

    /// Loads multiple roles from `Vec<Role>`
    pub fn load_roles(&mut self, roles: Vec<Role>) -> &mut Self {
        for role in roles {
            self.add_role(role);
        }
        self
    }

    /// Sets new fallback roles (roles that checked in user doesn't have any). Updater would ignore this, if None and leave old ones in affected service.
    pub fn set_fallback_roles(&mut self, fallback_roles: Vec<String>) -> &Self {
        self.fallback_roles = Some(fallback_roles);
        self
    }

    pub fn update(&self, rbac_service: &RbacService) {
        rbac_service.roles.swap(Arc::new(self.roles.clone()));
    }
}

impl RbacService {
    /// Creates builder ([RbacServiceBuilder]) for [RbacService]
    pub fn builder() -> RbacServiceBuilder {
        RbacServiceBuilder {
            roles: HashMap::new(),
            fallback_roles: None,
            all_permissions: BTreeMap::new(),
        }
    }
    /// Creates clean updater ([RbacServiceBuilder]) for updating [RbacService] roles in runtime.
    /// Updated roles set would be swapped atomically, when [updater.update(&mut rbac_service)][RbacServiceUpdater#method.update] called.
    pub fn updater_clean(&self) -> RbacServiceUpdater {
        RbacServiceUpdater {
            roles: HashMap::new(),
            fallback_roles: None,
        }
    }

    /// Creates updater ([RbacServiceBuilder]) for updating [RbacService] roles in runtime. 
    /// Updater would have copy of roles, which may be handy in case if small number of roles should be added/updated/removed
    pub fn updater_copy(&self) -> RbacServiceUpdater {
        RbacServiceUpdater {
            roles: self.roles.load().as_ref().clone(),
            fallback_roles: None,
        }
    }

    /// Check if subject has a specific permission
    pub fn has_permission<P: Permission>(
        &self,
        subject: &impl RbacSubject,
        permission: P,
    ) -> Result<(), RbacError> {
        let perm_str = permission.to_permission_string();
        let domain = P::domain();
        let object_type = permission.object_type();
        let subject_roles = subject.get_roles();
        let subject_roles = if subject_roles.is_empty() {
            &self.fallback_roles
        } else {
            subject_roles
        };

        let inner_roles = self.roles.load();

        // Collect all permissions from user's roles
        for role_name in subject_roles {
            let role = match inner_roles.get(role_name) {
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

    pub fn get_all_permissions(&self) -> Vec<&PermissionInfo> {
        self.all_permissions.values().collect()
    }

    pub fn get(&self, perm: &str) -> Option<&PermissionInfo> {
        self.all_permissions.get(perm)
    }
}
