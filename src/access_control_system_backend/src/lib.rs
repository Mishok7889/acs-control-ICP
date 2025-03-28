use candid::{CandidType, Deserialize, Principal};
use ic_cdk::api::call::CallResult;
use ic_cdk::{caller, trap};
use ic_cdk_macros::*;
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::{DefaultMemoryImpl, StableBTreeMap};
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};

// Define memory and stable structures
type Memory = VirtualMemory<DefaultMemoryImpl>;

// Define the core structures for our Access Control System

#[derive(CandidType, Clone, Deserialize, Debug, PartialEq, Eq, Hash)]
pub enum Role {
    Admin,
    Manager,
    User,
    Guest,
}

#[derive(CandidType, Clone, Deserialize, Debug, PartialEq, Eq)]
pub enum RequestStatus {
    Pending,
    Approved,
    Denied,
}

#[derive(CandidType, Clone, Deserialize, Debug)]
pub struct AccessRequest {
    id: String,
    requester: Principal,
    resource: String,
    requested_at: u64,
    status: RequestStatus,
    processed: bool,
}

// Implement Storable for AccessRequest
impl ic_stable_structures::Storable for AccessRequest {
    fn to_bytes(&self) -> std::borrow::Cow<[u8]> {
        let bytes = candid::encode_one(self).unwrap();
        std::borrow::Cow::Owned(bytes)
    }

    fn from_bytes(bytes: std::borrow::Cow<[u8]>) -> Self {
        candid::decode_one(&bytes).unwrap()
    }
    
    // Define maximum byte size (required for BOUND)
    const BOUND: ic_stable_structures::storable::Bound = ic_stable_structures::storable::Bound::Unbounded;
}

// Define processing guard to prevent double processing
pub struct RequestProcessingGuard {
    request_id: String,
}

impl RequestProcessingGuard {
    pub fn new(request_id: String) -> Result<Self, String> {
        // Verify the request exists and is not already processed
        let request_exists = ACCESS_REQUESTS.with(|requests| {
            requests.borrow().get(&request_id).is_some()
        });
        
        if !request_exists {
            return Err("Request does not exist".to_string());
        }
        
        let is_pending = PENDING_REQUESTS.with(|pending| {
            pending.borrow().contains(&request_id)
        });
        
        if !is_pending {
            return Err("Request is not pending".to_string());
        }
        
        let is_processed = ACCESS_REQUESTS.with(|requests| {
            requests.borrow().get(&request_id)
                .map(|req| req.processed)
                .unwrap_or(false)
        });
        
        if is_processed {
            return Err("Request has already been processed".to_string());
        }
        
        // Add to processing requests set
        PROCESSING_REQUESTS.with(|processing| {
            if !processing.borrow_mut().insert(request_id.clone()) {
                return Err("Request is already being processed".to_string());
            }
            Ok(())
        })?;
        
        Ok(Self { request_id })
    }
}

impl Drop for RequestProcessingGuard {
    fn drop(&mut self) {
        // Remove from processing set when guard is dropped
        PROCESSING_REQUESTS.with(|processing| {
            processing.borrow_mut().remove(&self.request_id);
        });
    }
}

// Thread-local storage for our state
thread_local! {
    // In-memory state
    static USERS: RefCell<HashMap<Principal, Role>> = RefCell::new(HashMap::new());
    static RESOURCE_PERMISSIONS: RefCell<HashMap<String, HashSet<Role>>> = RefCell::new(HashMap::new());
    static PENDING_REQUESTS: RefCell<HashSet<String>> = RefCell::new(HashSet::new());
    static PROCESSING_REQUESTS: RefCell<HashSet<String>> = RefCell::new(HashSet::new());
    
    // Stable storage
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> = 
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));
    
    static ACCESS_REQUESTS: RefCell<StableBTreeMap<String, AccessRequest, Memory>> = RefCell::new(
        StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(0)))
        )
    );
}

// Initialize the canister
#[init]
fn init() {
    let caller = caller();
    USERS.with(|users| {
        users.borrow_mut().insert(caller, Role::Admin);
    });
    
    ic_cdk::println!("Access Control System initialized with admin: {}", caller.to_string());
}

// Add a post_upgrade function to ensure the upgrader becomes admin
#[post_upgrade]
fn post_upgrade() {
    let caller = caller();
    USERS.with(|users| {
        // Always ensure the upgrader is admin
        users.borrow_mut().insert(caller, Role::Admin);
    });
    
    ic_cdk::println!("Access Control System upgraded by admin: {}", caller.to_string());
}

#[update]
fn bootstrap_admin() -> bool {
    let admin_exists = USERS.with(|users| {
        users.borrow().values().any(|role| *role == Role::Admin)
    });
    
    if !admin_exists {
        let caller = caller();
        USERS.with(|users| {
            users.borrow_mut().insert(caller, Role::Admin);
        });
        ic_cdk::println!("Bootstrapped first admin: {}", caller.to_string());
        true
    } else {
        ic_cdk::println!("Cannot bootstrap admin: admins already exist");
        false
    }
}

// ===== User Management Functions =====

#[update(guard = "is_admin")]
fn add_user(user: Principal, role: Role) {
    let role_clone = role.clone();
    USERS.with(|users| {
        users.borrow_mut().insert(user, role);
    });
    
    let role_str = format!("{:?}", role_clone);
    ic_cdk::println!("User {} added with role {}", user.to_string(), role_str);
}

#[update(guard = "is_admin")]
fn remove_user(user: Principal) {
    USERS.with(|users| {
        users.borrow_mut().remove(&user);
    });
    
    ic_cdk::println!("User {} removed", user.to_string());
}

#[query]
fn get_user_role(user: Principal) -> Option<Role> {
    USERS.with(|users| {
        users.borrow().get(&user).cloned()
    })
}

// ===== Resource Permission Management =====

#[update(guard = "is_admin_or_manager")]
fn add_resource_permission(resource: String, allowed_role: Role) {
    RESOURCE_PERMISSIONS.with(|permissions| {
        permissions
            .borrow_mut()
            .entry(resource.clone())
            .or_insert_with(HashSet::new)
            .insert(allowed_role.clone());
    });
    
    ic_cdk::println!("Permission for role {:?} added to resource {}", allowed_role, resource);
}

#[update(guard = "is_admin_or_manager")]
fn remove_resource_permission(resource: String, role: Role) {
    RESOURCE_PERMISSIONS.with(|permissions| {
        if let Some(roles) = permissions.borrow_mut().get_mut(&resource) {
            roles.remove(&role);
        }
    });
    
    ic_cdk::println!("Permission for role {:?} removed from resource {}", role, resource);
}

#[query]
fn can_access_resource(user: Principal, resource: String) -> bool {
    let user_role = match get_user_role(user) {
        Some(role) => role,
        None => return false,
    };
    
    // Admins can access everything
    if user_role == Role::Admin {
        return true;
    }
    
    RESOURCE_PERMISSIONS.with(|permissions| {
        permissions
            .borrow()
            .get(&resource)
            .map_or(false, |roles| roles.contains(&user_role))
    })
}

// ===== Access Request Processing =====

#[update]
fn request_access(resource: String) -> String {
    let requester = caller();
    let request_id = format!("req-{}-{}", requester.to_text(), ic_cdk::api::time());
    
    let request = AccessRequest {
        id: request_id.clone(),
        requester,
        resource,
        requested_at: ic_cdk::api::time(),
        status: RequestStatus::Pending,
        processed: false,
    };
    
    // Store the request
    ACCESS_REQUESTS.with(|requests| {
        requests.borrow_mut().insert(request_id.clone(), request);
    });
    
    // Track pending request
    PENDING_REQUESTS.with(|pending| {
        pending.borrow_mut().insert(request_id.clone());
    });
    
    ic_cdk::println!("Access request created: {}", request_id);
    request_id
}

#[update(guard = "is_admin_or_manager")]
async fn process_request(request_id: String, approve: bool) {
    // Create a processing guard that will ensure the request is processed at most once
    // and protect against parallel processing
    let guard = match RequestProcessingGuard::new(request_id.clone()) {
        Ok(guard) => guard,
        Err(e) => trap(&e),
    };
    
    // Create a scope guard to mark the request as processed if this function completes
    // This will execute even if the async code fails
    let request_id_clone = request_id.clone();
    let _complete_guard = scopeguard::guard((), move |_| {
        // Mark the request as processed and update status
        let status = if approve {
            RequestStatus::Approved
        } else {
            RequestStatus::Denied
        };
        
        // Get and update the request
        let mut updated_request = ACCESS_REQUESTS.with(|requests| {
            requests.borrow().get(&request_id_clone).unwrap().clone()
        });
        
        updated_request.status = status.clone();
        updated_request.processed = true;
        
        // Update in storage
        ACCESS_REQUESTS.with(|requests| {
            requests.borrow_mut().insert(request_id_clone.clone(), updated_request);
        });
        
        // Remove from pending
        PENDING_REQUESTS.with(|pending| {
            pending.borrow_mut().remove(&request_id_clone);
        });
        
        ic_cdk::println!("Request {} processed with status: {:?}", request_id_clone, status);
    });
    
    // Simulate external call or processing
    // This is the async part where we might yield control
    let result = simulate_external_processing(request_id.clone(), approve).await;
    
    // Handle potential errors from async processing
    if let Err(e) = result {
        ic_cdk::println!("Error in async processing for request {}: {:?}", request_id, e);
        // We don't need to do anything special here, as the scope guard will still execute
        // and update the request accordingly
    }
    
    // The _complete_guard will be executed when this function returns,
    // ensuring the request is marked as processed even if something fails later
}

// Simulates an external async call
async fn simulate_external_processing(request_id: String, _approve: bool) -> CallResult<()> {
    // Simulate an external call
    ic_cdk::println!("Starting async processing for request: {}", request_id);
    
    // In a real system, this would be an inter-canister call
    // Use raw_rand to guarantee true async behavior that yields control
    let _ = ic_cdk::api::management_canister::main::raw_rand().await;
    
    Ok(())
}

#[query]
fn get_request_status(request_id: String) -> Option<RequestStatus> {
    ACCESS_REQUESTS.with(|requests| {
        requests.borrow().get(&request_id).map(|req| req.status.clone())
    })
}

#[query]
fn get_all_pending_requests() -> Vec<String> {
    PENDING_REQUESTS.with(|pending| {
        pending.borrow().iter().cloned().collect()
    })
}

// ===== Guard Functions =====

fn is_admin() -> Result<(), String> {
    let caller = caller();
    let is_admin = USERS.with(|users| {
        users.borrow().get(&caller).map_or(false, |role| *role == Role::Admin)
    });
    
    if is_admin {
        Ok(())
    } else {
        Err("Caller is not an admin".to_string())
    }
}

fn is_admin_or_manager() -> Result<(), String> {
    let caller = caller();
    let has_permission = USERS.with(|users| {
        users.borrow().get(&caller).map_or(false, |role| {
            *role == Role::Admin || *role == Role::Manager
        })
    });
    
    if has_permission {
        Ok(())
    } else {
        Err("Caller must be an admin or manager".to_string())
    }
}

// ===== Candid Interface Export =====

#[query(name = "__get_candid_interface_tmp_hack")]
fn export_candid() -> String {
    include_str!("../access_control_system_backend.did").to_string()
}

// Candid generation
ic_cdk::export_candid!();