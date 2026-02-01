# SafeVault - Phase 2: Authentication & Authorization (RBAC)

## Overview

Phase 2 implements secure authentication and role-based access control (RBAC):

- ✅ User authentication with secure password hashing (PBKDF2/SHA256)
- ✅ Role-based access control (Admin, User roles)
- ✅ Admin dashboard with protected resources
- ✅ Comprehensive authorization tests

## Project Structure (Phase 2 Additions)

```
SafeVault/
├── Models/
│   ├── User.cs                          # Extended with Role & LastLoginAt
│   └── UserRole.cs                      # Enum: Admin, User
├── Services/
│   ├── AuthenticationService.cs         # NEW: Password hashing & login
│   ├── AuthorizationService.cs          # NEW: RBAC & resource access
│   └── InputValidationService.cs        # Phase 1
├── Repositories/
│   └── UserRepository.cs                # Extended with role management
├── Views/
│   ├── Auth/
│   │   ├── Login.cshtml                 # NEW: Login form
│   │   └── Register.cshtml              # Phase 1
│   └── Admin/
│       └── Dashboard.cshtml             # NEW: Admin-only dashboard
├── Tests/
│   ├── AuthenticationServiceTests.cs    # NEW: 14+ auth tests
│   ├── AuthorizationServiceTests.cs     # NEW: 13+ RBAC tests
│   ├── InputValidationServiceTests.cs   # Phase 1
│   └── UserRepositoryTests.cs           # Phase 1
└── README.md
```

## Key Security Features

### 1. Authentication (`AuthenticationService.cs`)

- **Password Hashing**: PBKDF2 with SHA256
  - 10,000 iterations
  - Random 16-byte salt
  - Timing-safe comparison to prevent timing attacks
- **Login Flow**:
  ```csharp
  var user = await authService.AuthenticateAsync(username, password);
  if (user != null) {
      // Authentication successful
      // LastLoginAt is updated
  }
  ```
- **Registration**:
  ```csharp
  await authService.RegisterAsync(username, email, password);
  // Validates all inputs, hashes password, creates user
  ```

### 2. Role-Based Authorization (RBAC) (`AuthorizationService.cs`)

- **Roles**:
  - `Admin`: Full system access
  - `User`: Limited access to own resources

- **Resource Protection**:

  ```csharp
  // Check admin dashboard access
  bool canAccess = AuthorizationService.CanAccessResource(user, "admin-dashboard");

  // Check specific action authorization
  bool canManageUsers = AuthorizationService.AuthorizeAction(user, "manage-users");
  ```

- **Protected Actions**:
  - Admin: `manage-users`, `view-audit-logs`, `manage-roles`, `view-system-settings`
  - User: `view-own-profile`, `edit-own-profile`, `delete-own-account`
  - Both: `user-data`, `user-profile`

### 3. Admin Dashboard (`Views/Admin/Dashboard.cshtml`)

- Protected resource for admins only
- Provides access to:
  - User management
  - System settings
  - Audit logs

## Test Coverage

### AuthenticationServiceTests.cs (14 tests)

- ✅ Password hashing with random salt
- ✅ Password verification (correct/incorrect)
- ✅ Valid/invalid authentication
- ✅ Registration with validation
- ✅ Weak password rejection
- ✅ Login timestamp tracking

### AuthorizationServiceTests.cs (13 tests)

- ✅ Role checking (Admin, User)
- ✅ Resource access control
- ✅ Action authorization
- ✅ Admin-only access
- ✅ Regular user access
- ✅ Null user handling

## Running Tests

```bash
# Restore packages
dotnet restore

# Run all tests (Phase 1 + Phase 2)
dotnet test

# Run authentication tests
dotnet test --filter "ClassName=AuthenticationServiceTests"

# Run authorization tests
dotnet test --filter "ClassName=AuthorizationServiceTests"

# Verbose output
dotnet test --verbosity detailed
```

## Usage Example

```csharp
// Register new user
var authService = new AuthenticationService(userRepository);
await authService.RegisterAsync("john_doe", "john@example.com", "SecurePass123!");

// Login user
var user = await authService.AuthenticateAsync("john_doe", "SecurePass123!");

// Check authorization
if (AuthorizationService.CanAccessResource(user, "admin-dashboard"))
{
    // Grant admin access
}
```

## Next Phase (Phase 3)

- Vulnerability audit (SQL injection + XSS vectors)
- Security hardening & fixes
- Attack simulation tests
- Security summary report

## Security Considerations

- ✅ Passwords never stored in plain text
- ✅ Each password has unique salt
- ✅ PBKDF2 with 10,000 iterations (slow hashing)
- ✅ Timing-safe password comparison
- ✅ Role-based access control enforced
- ✅ Admin resources protected by authorization checks
- ⚠️ Production: Consider bcrypt or Argon2 for stronger hashing
- ⚠️ Production: Implement JWT tokens or session management

---

**Status**: ✅ Phase 2 Complete - Ready for review
