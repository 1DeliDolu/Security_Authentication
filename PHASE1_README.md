# SafeVault - Phase 1: Secure Code & Input Validation

## Overview

Phase 1 of SafeVault implements secure coding practices with focus on:

- ✅ Input validation (username, email, password strength)
- ✅ Parameterized queries (SQL injection prevention)
- ✅ HTML sanitization (XSS prevention)
- ✅ Comprehensive unit tests

## Project Structure

```
SafeVault/
├── Models/
│   └── User.cs                          # User entity with validation attributes
├── Data/
│   └── SafeVaultDbContext.cs            # EF Core context with parameterized queries
├── Services/
│   └── InputValidationService.cs        # Input validation & sanitization
├── Repositories/
│   └── UserRepository.cs                # User CRUD with secure queries
├── Views/
│   └── Auth/
│       └── Register.cshtml              # Registration form with client-side validation
├── Tests/
│   ├── InputValidationServiceTests.cs   # XSS & input validation tests
│   └── UserRepositoryTests.cs           # SQL injection & parameterized query tests
├── SafeVault.csproj
└── README.md
```

## Key Security Features

### 1. Input Validation (`InputValidationService.cs`)

- **Username**: Alphanumeric + underscore only, 3-50 characters
- **Email**: RFC-compliant email validation
- **Password**: Min 8 chars with uppercase, lowercase, digit, special character
- **XSS Prevention**: `SanitizeHtml()` escapes HTML entities

### 2. Parameterized Queries (`UserRepository.cs`)

- Uses Entity Framework Core LINQ (automatically parameterized)
- No string concatenation or dynamic SQL
- All user input treated as data, not executable code
- Examples:

  ```csharp
  // ✅ SECURE: Parameterized
  var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == username);

  // ❌ INSECURE (NOT USED): String concatenation
  // var user = await _context.Users.FromSqlRaw($"SELECT * FROM Users WHERE Username = '{username}'");
  ```

### 3. XSS Prevention

- HTML encoding via `System.Net.WebUtility.HtmlEncode()`
- Form input restrictions (regex patterns)
- Test coverage for common XSS payloads:
  - `<script>alert('XSS')</script>`
  - `<img src=x onerror='alert()'>`
  - `<iframe src='javascript:alert(1)'>`

## Test Coverage

### InputValidationServiceTests.cs

- ✅ Valid/invalid username formats
- ✅ Valid/invalid email formats
- ✅ HTML escaping (XSS prevention)
- ✅ Password strength validation
- ✅ Common XSS attack patterns

### UserRepositoryTests.cs

- ✅ SQL injection attempts (`'; DROP TABLE Users; --`)
- ✅ Blind SQL injection (`' OR '1'='1`)
- ✅ XSS payloads in input fields
- ✅ Parameterized query execution
- ✅ Duplicate user prevention

## Running Tests

```bash
# Restore packages
dotnet restore

# Run all tests
dotnet test

# Run with verbose output
dotnet test --verbosity detailed

# Run specific test class
dotnet test --filter "ClassName=InputValidationServiceTests"
```

## Next Phase (Phase 2)

- Authentication with bcrypt/Argon2
- Role-based access control (RBAC)
- Admin dashboard protection
- JWT token generation

## Next Phase (Phase 3)

- Vulnerability audit
- Debugging & hardening
- Attack simulation tests
- Security summary report

---

**Status**: ✅ Phase 1 Complete - Ready for review
