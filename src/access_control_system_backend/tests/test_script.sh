#########################
# 1. INITIAL SETUP
#########################

# Make sure you're using your admin identity
dfx identity use default

# Create an anonymous user (valid principal)
dfx canister call access_control_system_backend add_user '(principal "2vxsx-fae", variant { User })'

# Create test identities for proper testing
dfx identity new manager-test
dfx identity use manager-test
MANAGER_PRINCIPAL=$(dfx identity get-principal)
echo "Manager principal: $MANAGER_PRINCIPAL"

dfx identity new user-test
dfx identity use user-test
USER_PRINCIPAL=$(dfx identity get-principal)
echo "User principal: $USER_PRINCIPAL"

dfx identity new guest-test
dfx identity use guest-test
GUEST_PRINCIPAL=$(dfx identity get-principal)
echo "Guest principal: $GUEST_PRINCIPAL"

# Switch back to admin
dfx identity use default

# Add the test identities with their roles
dfx canister call access_control_system_backend add_user "(principal \"$MANAGER_PRINCIPAL\", variant { Manager })"
dfx canister call access_control_system_backend add_user "(principal \"$USER_PRINCIPAL\", variant { User })"
dfx canister call access_control_system_backend add_user "(principal \"$GUEST_PRINCIPAL\", variant { Guest })"

#########################
# 2. VERIFY ROLES
#########################

# Check your own role (should be Admin)
MY_PRINCIPAL=$(dfx identity get-principal)
dfx canister call access_control_system_backend get_user_role "(principal \"$MY_PRINCIPAL\")"
# Expected: (opt variant { Admin })

# Check other roles
dfx canister call access_control_system_backend get_user_role "(principal \"$MANAGER_PRINCIPAL\")"
# Expected: (opt variant { Manager })

dfx canister call access_control_system_backend get_user_role "(principal \"$USER_PRINCIPAL\")"
# Expected: (opt variant { User })

dfx canister call access_control_system_backend get_user_role "(principal \"$GUEST_PRINCIPAL\")"
# Expected: (opt variant { Guest })

dfx canister call access_control_system_backend get_user_role '(principal "2vxsx-fae")'
# Expected: (opt variant { User })

#########################
# 3. RESOURCE PERMISSIONS
#########################

# Add resource permissions
dfx canister call access_control_system_backend add_resource_permission '("confidential.pdf", variant { Admin })'
dfx canister call access_control_system_backend add_resource_permission '("confidential.pdf", variant { Manager })'

dfx canister call access_control_system_backend add_resource_permission '("internal.pdf", variant { Admin })'
dfx canister call access_control_system_backend add_resource_permission '("internal.pdf", variant { Manager })'
dfx canister call access_control_system_backend add_resource_permission '("internal.pdf", variant { User })'

dfx canister call access_control_system_backend add_resource_permission '("public.pdf", variant { Admin })'
dfx canister call access_control_system_backend add_resource_permission '("public.pdf", variant { Manager })'
dfx canister call access_control_system_backend add_resource_permission '("public.pdf", variant { User })'
dfx canister call access_control_system_backend add_resource_permission '("public.pdf", variant { Guest })'

# Check access permissions (as admin)
dfx canister call access_control_system_backend can_access_resource "(principal \"$MY_PRINCIPAL\", \"confidential.pdf\")"
# Expected: (true) - Admin can access everything

dfx canister call access_control_system_backend can_access_resource "(principal \"$MANAGER_PRINCIPAL\", \"confidential.pdf\")"
# Expected: (true) - Manager can access confidential resources

dfx canister call access_control_system_backend can_access_resource "(principal \"$USER_PRINCIPAL\", \"confidential.pdf\")"
# Expected: (false) - User cannot access confidential resources

dfx canister call access_control_system_backend can_access_resource "(principal \"$USER_PRINCIPAL\", \"internal.pdf\")"
# Expected: (true) - User can access internal resources

dfx canister call access_control_system_backend can_access_resource "(principal \"$GUEST_PRINCIPAL\", \"internal.pdf\")"
# Expected: (false) - Guest cannot access internal resources

dfx canister call access_control_system_backend can_access_resource "(principal \"$GUEST_PRINCIPAL\", \"public.pdf\")"
# Expected: (true) - Guest can access public resources

#########################
# 4. ACCESS REQUESTS
#########################

# Switch to user identity to make requests
dfx identity use user-test

# Request access to a confidential resource (that users can't normally access)
dfx canister call access_control_system_backend request_access '("confidential.pdf")'
# Save the request ID returned (it will look like "req-principal-timestamp")
# For example:
REQUEST_ID="req-YOUR_REQUEST_ID_HERE"
echo "Request ID: $REQUEST_ID"

# Switch back to admin to view and process requests
dfx identity use default

# Check pending requests
dfx canister call access_control_system_backend get_all_pending_requests
# Expected: A vector containing the request ID

# Check the status of our specific request
dfx canister call access_control_system_backend get_request_status "(\"$REQUEST_ID\")"
# Expected: (opt variant { Pending })

# Process the request (approve it)
dfx canister call access_control_system_backend process_request "(\"$REQUEST_ID\", true)"

# Verify the request status has been updated
dfx canister call access_control_system_backend get_request_status "(\"$REQUEST_ID\")"
# Expected: (opt variant { Approved })

# Check that there are no more pending requests
dfx canister call access_control_system_backend get_all_pending_requests
# Expected: (vec {})

# Try to process the same request again (should fail with error)
dfx canister call access_control_system_backend process_request "(\"$REQUEST_ID\", true)"
# Expected: Error - Request has already been processed

#########################
# 5. TESTING GUARD PATTERN
#########################

# Switch to guest identity (which doesn't have manager privileges)
dfx identity use guest-test

# Try to add resource permissions (should fail)
dfx canister call access_control_system_backend add_resource_permission '("test_resource.pdf", variant { Guest })'
# Expected: Error - Caller must be an admin or manager

# Try to process a request (should fail)
dfx canister call access_control_system_backend process_request "(\"$REQUEST_ID\", true)"
# Expected: Error - Caller must be an admin or manager

# Create another request to test denial
dfx canister call access_control_system_backend request_access '("internal.pdf")'
# Save this request ID
REQUEST_ID2="req-YOUR_SECOND_REQUEST_ID_HERE"
echo "Second Request ID: $REQUEST_ID2"

# Switch to manager identity (which has permission to process requests)
dfx identity use manager-test

# Process the second request (deny it)
dfx canister call access_control_system_backend process_request "(\"$REQUEST_ID2\", false)"

# Check the request status
dfx canister call access_control_system_backend get_request_status "(\"$REQUEST_ID2\")"
# Expected: (opt variant { Denied })

#########################
# 6. USER MANAGEMENT EXTRAS
#########################

# Switch back to admin
dfx identity use default

# Remove a user
dfx canister call access_control_system_backend remove_user "(principal \"$GUEST_PRINCIPAL\")"

# Verify the user has been removed
dfx canister call access_control_system_backend get_user_role "(principal \"$GUEST_PRINCIPAL\")"
# Expected: (null)

# Verify the user can no longer access resources
dfx canister call access_control_system_backend can_access_resource "(principal \"$GUEST_PRINCIPAL\", \"public.pdf\")"
# Expected: (false) - Removed user has no access

# Clean up test identities when done
# dfx identity use default
# dfx identity remove manager-test
# dfx identity remove user-test
# dfx identity remove guest-test