# Access Control Management System

A robust role-based access control system built on the Internet Computer, featuring guard patterns to enforce security invariants even with asynchronous code execution.

## System Capabilities

### Role-Based Access Control
- **User Roles**: Admin, Manager, User, and Guest roles with different permission levels
- **Resource Permissions**: Configure which roles can access specific resources
- **Fine-grained Control**: Each resource can have different permission requirements

### Access Request Workflow
- Users can request access to resources they don't have permission for
- Admins/Managers can approve or deny access requests
- Request status tracking (Pending, Approved, Denied)

### Security Features
- **Guard Patterns**: Enforces security invariants with asynchronous code
- **Double-processing prevention**: Each request can only be processed once
- **Stable Storage**: Uses IC stable storage for data persistence across upgrades

### Key Architectural Elements
- Thread-local state management for both in-memory and stable storage
- Advanced async processing with RAII-based guards to maintain system integrity
- Protection against parallel processing and double-processing
- Scope guards for transaction-like behavior
- Role-based permission enforcement

## How It Works

### Advanced Guard Pattern Implementation

The system implements sophisticated guard patterns to enforce critical security invariants even with asynchronous code:

```rust
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
        // ...
    });
    
    // Simulate external call or processing
    let result = simulate_external_processing(request_id.clone(), approve).await;
    
    // The _complete_guard will be executed when this function returns,
    // ensuring the request is marked as processed even if something fails later
}
```

The guard structure uses the RAII (Resource Acquisition Is Initialization) pattern with Rust's `Drop` trait:

```rust
pub struct RequestProcessingGuard {
    request_id: String,
}

impl RequestProcessingGuard {
    pub fn new(request_id: String) -> Result<Self, String> {
        // Validation logic to ensure request can be processed
        // ...
        
        // Add to processing requests set to prevent parallel processing
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
```

This comprehensive approach provides multiple layers of protection:

1. **Double-processing prevention**: Each request is processed at most once
2. **Parallel processing protection**: The same request cannot be processed concurrently
3. **Transaction-like behavior**: Using scope guards ensures operations complete properly
4. **Automatic cleanup**: The Drop trait ensures resources are released even if processing fails

## Installation and Deployment

### Prerequisites
- [dfx](https://internetcomputer.org/docs/current/developer-docs/setup/install/) (Internet Computer SDK) installed
- Rust and cargo installed
- Required dependencies in Cargo.toml:
  ```toml
  [dependencies]
  candid = "0.10"
  ic-cdk = "0.17"
  ic-cdk-timers = "0.11"
  ic-cdk-macros = "0.17.1"
  serde = { version = "1.0", features = ["derive"] }
  serde_json = "1.0"
  hex = "0.4.3"
  ic-stable-structures = "0.6.8"
  scopeguard = "1.2.0"  # For advanced guard patterns
  ```

### Setup
1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd access-control-system
   ```

2. Start the local Internet Computer replica:
   ```bash
   dfx start --background
   ```

3. Deploy the canister:
   ```bash
   dfx deploy
   ```

### Deployment to IC Mainnet
1. Configure your identity:
   ```bash
   dfx identity use <your-identity>
   ```

2. Deploy to the mainnet:
   ```bash
   dfx deploy --network ic
   ```

## Testing the System

### Manual Testing with CLI

Here's how to test the system using dfx commands:

#### 1. Set up test identities
```bash
# Create test identities
dfx identity new manager-test
dfx identity use manager-test
MANAGER_PRINCIPAL=$(dfx identity get-principal)
echo "Manager principal: $MANAGER_PRINCIPAL"

dfx identity new user-test
dfx identity use user-test
USER_PRINCIPAL=$(dfx identity get-principal)
echo "User principal: $USER_PRINCIPAL"

# Switch back to admin identity
dfx identity use default
```

#### 2. Add users with roles
```bash
# Add users with different roles
dfx canister call access_control_system_backend add_user "(principal \"$MANAGER_PRINCIPAL\", variant { Manager })"
dfx canister call access_control_system_backend add_user "(principal \"$USER_PRINCIPAL\", variant { User })"
```

#### 3. Configure resource permissions
```bash
# Add resource permissions
dfx canister call access_control_system_backend add_resource_permission '("confidential.pdf", variant { Admin })'
dfx canister call access_control_system_backend add_resource_permission '("confidential.pdf", variant { Manager })'
dfx canister call access_control_system_backend add_resource_permission '("public.pdf", variant { Admin })'
dfx canister call access_control_system_backend add_resource_permission '("public.pdf", variant { Manager })'
dfx canister call access_control_system_backend add_resource_permission '("public.pdf", variant { User })'
```

#### 4. Test access control
```bash
# Check access permissions
dfx canister call access_control_system_backend can_access_resource "(principal \"$USER_PRINCIPAL\", \"confidential.pdf\")"
# Expected: (false)

dfx canister call access_control_system_backend can_access_resource "(principal \"$USER_PRINCIPAL\", \"public.pdf\")"
# Expected: (true)
```

#### 5. Test the request workflow
```bash
# Switch to user identity
dfx identity use user-test

# Request access to confidential resource
dfx canister call access_control_system_backend request_access '("confidential.pdf")'
# Save the request ID returned
REQUEST_ID="req-xxxx-yyyy-timestamp"

# Switch to admin
dfx identity use default

# Check pending requests
dfx canister call access_control_system_backend get_all_pending_requests

# Process the request (approve)
dfx canister call access_control_system_backend process_request "(\"$REQUEST_ID\", true)"

# Check request status
dfx canister call access_control_system_backend get_request_status "(\"$REQUEST_ID\")"
# Expected: (opt variant { Approved })
```

### Automated Testing

You can also run the automated test script:

```bash
# Make the script executable
chmod +x scripts/test_access_control.sh

# Run the tests
./scripts/test_access_control.sh
```

## System Architecture

### Key Components
- **User Management**: Role assignment and verification
- **Resource Permissions**: Configurable access levels for resources
- **Access Request System**: Request creation, tracking, and processing
- **Guard Pattern**: Ensures security invariants with async code

### Data Model
- **Role Enum**: Admin, Manager, User, Guest
- **AccessRequest**: Tracks request details and status
- **RequestStatus**: Pending, Approved, Denied

### Security Considerations
1. Only admins can manage users
2. Admin/Managers can manage resource permissions
3. Guard patterns prevent race conditions in async processing
4. Stable storage ensures data persistence across upgrades

## Use Cases

### 1. Document Management System
Control access to sensitive documents, with approval workflows for access to confidential materials.

### 2. Resource Allocation System
Manage access to limited resources, with managers approving or denying requests.

### 3. Secure API Access
Control which roles can access specific API endpoints or services.

## Future Enhancements

- **Temporary Access**: Grant time-limited access to resources
- **Delegation**: Allow admins to delegate approval authority
- **Audit Logging**: Track all access and permission changes
- **Frontend Interface**: Create a web UI for easier system management

---

Built for the Internet Computer Platform using Rust and Candid.