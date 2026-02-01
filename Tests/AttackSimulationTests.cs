using Xunit;
using SafeVault.Services;

namespace SafeVault.Tests
{
    /// <summary>
    /// Attack simulation tests to verify that security vulnerabilities are properly mitigated.
    /// Tests simulate real-world attack scenarios: SQL injection and XSS attacks.
    /// </summary>
    public class AttackSimulationTests
    {
        #region SQL Injection Attack Simulations

        [Theory]
        [InlineData("'; DROP TABLE Users; --")]
        [InlineData("' OR '1'='1")]
        [InlineData("' UNION SELECT * FROM Users --")]
        [InlineData("admin' --")]
        [InlineData("' OR 1=1 --")]
        public async Task SQLInjectionAttack_ParameterizedQuery_Blocked(string sqlInjectionPayload)
        {
            // Arrange
            var context = CreateInMemoryContext();
            var repository = new UserRepository(context);

            // Add legitimate user
            var user = new User
            {
                Username = "admin",
                Email = "admin@example.com",
                PasswordHash = "hash"
            };
            context.Users.Add(user);
            await context.SaveChangesAsync();

            // Act
            // SQL injection payload should be treated as literal string, not SQL code
            var result = await repository.GetUserByUsernameAsync(sqlInjectionPayload);

            // Assert
            // Should return null (no user with that literal username)
            Assert.Null(result);

            // Verify legitimate user still exists (table not dropped, etc.)
            var legitUser = await repository.GetUserByUsernameAsync("admin");
            Assert.NotNull(legitUser);
        }

        [Fact]
        public async Task SQLInjectionAttack_UnionBasedInjection_Blocked()
        {
            // Arrange
            var context = CreateInMemoryContext();
            var repository = new UserRepository(context);

            // Setup users
            await repository.CreateUserAsync("user1", "user1@example.com", "hash1");
            await repository.CreateUserAsync("user2", "user2@example.com", "hash2");

            // Act
            // Attacker tries UNION-based injection to extract all users
            string injectionPayload = "' UNION SELECT UserId, Username, Email, PasswordHash, 0, NULL FROM Users --";
            var result = await repository.GetUserByUsernameAsync(injectionPayload);

            // Assert
            Assert.Null(result); // No user with that literal username
        }

        [Fact]
        public async Task SQLInjectionAttack_TimeBasedBlindInjection_Blocked()
        {
            // Arrange
            var context = CreateInMemoryContext();
            var repository = new UserRepository(context);

            // Act
            // Time-based blind SQL injection: ' OR SLEEP(5) --
            string injectionPayload = "' OR SLEEP(5) --";
            var stopwatch = System.Diagnostics.Stopwatch.StartNew();
            var result = await repository.GetUserByUsernameAsync(injectionPayload);
            stopwatch.Stop();

            // Assert
            Assert.Null(result);
            // Should complete quickly (< 1 second), not hang from SLEEP
            Assert.True(stopwatch.ElapsedMilliseconds < 1000);
        }

        #endregion

        #region XSS Attack Simulations

        [Theory]
        [InlineData("<script>alert('XSS')</script>")]
        [InlineData("<img src=x onerror='alert(\"XSS\")'>")]
        [InlineData("<svg onload='alert(1)'>")]
        [InlineData("<iframe src='javascript:alert(1)'></iframe>")]
        [InlineData("<body onload='alert(1)'>")]
        [InlineData("<input onfocus='alert(1)'>")]
        public void XSSAttack_ScriptInjection_Escaped(string xssPayload)
        {
            // Act
            string sanitized = InputValidationService.SanitizeHtml(xssPayload);

            // Assert
            // Should be HTML-encoded, not executable
            Assert.DoesNotContain("<script", sanitized);
            Assert.DoesNotContain("<img", sanitized);
            Assert.DoesNotContain("<svg", sanitized);
            Assert.DoesNotContain("<iframe", sanitized);
            Assert.DoesNotContain("onerror=", sanitized);
            Assert.DoesNotContain("onload=", sanitized);
            Assert.Contains("&lt;", sanitized); // Should contain encoded entities
        }

        [Theory]
        [InlineData("javascript:alert(1)")]
        [InlineData("data:text/html,<script>alert(1)</script>")]
        [InlineData("vbscript:msgbox(1)")]
        public void XSSAttack_ProtocolBasedXSS_Escaped(string xssPayload)
        {
            // Arrange
            string formattedPayload = $"<a href='{xssPayload}'>Click</a>";

            // Act
            string sanitized = InputValidationService.SanitizeHtml(formattedPayload);

            // Assert
            Assert.DoesNotContain("javascript:", sanitized);
            Assert.DoesNotContain("data:text/html", sanitized);
            Assert.DoesNotContain("vbscript:", sanitized);
        }

        [Fact]
        public void XSSAttack_StoredXSS_Simulation()
        {
            // Arrange
            // Attacker submits malicious content through registration
            string maliciousUsername = "<img src=x onerror='alert(\"Stored XSS\")'>";

            // Act
            // Validation should reject it
            bool isValid = InputValidationService.ValidateUsername(maliciousUsername);

            // Assert
            Assert.False(isValid); // Rejected by username format validation
        }

        [Fact]
        public void XSSAttack_ReflectedXSS_Escaped()
        {
            // Arrange
            // Attacker crafts URL: /search?q=<script>alert('XSS')</script>
            string userInput = "<script>alert('Reflected XSS')</script>";

            // Act
            string sanitized = InputValidationService.SanitizeHtml(userInput);

            // Assert
            Assert.DoesNotContain("<script>", sanitized);
            Assert.DoesNotContain("</script>", sanitized);
        }

        [Theory]
        [InlineData("&lt;script&gt;alert('XSS')&lt;/script&gt;")] // Already encoded
        [InlineData("&#60;script&#62;alert('XSS')&#60;/script&#62;")] // Numeric entities
        public void XSSAttack_DoubleEncodingBypass_Handled(string doubleEncodedXSS)
        {
            // Act
            string result = InputValidationService.SanitizeHtml(doubleEncodedXSS);

            // Assert
            // Should remain safe (not decode dangerous content)
            Assert.DoesNotContain("<script", result);
        }

        #endregion

        #region Combined Attack Scenarios

        [Fact]
        public async Task CombinedAttack_SQLInjectionWithXSS_Blocked()
        {
            // Arrange
            var context = CreateInMemoryContext();
            var repository = new UserRepository(context);

            // Attacker tries SQL injection + XSS: ' OR '1'='1<script>alert(1)</script>
            string combinedPayload = "' OR '1'='1<script>alert(1)</script>";

            // Act
            var result = await repository.GetUserByUsernameAsync(combinedPayload);

            // Assert
            Assert.Null(result);
        }

        [Fact]
        public async Task CredentialStuffing_WeakCredentials_Prevented()
        {
            // Arrange
            var context = CreateInMemoryContext();
            var repository = new UserRepository(context);
            var authService = new AuthenticationService(repository);

            // User registers with weak password
            string weakPassword = "weak"; // Fails strength validation

            // Act & Assert
            await Assert.ThrowsAsync<ArgumentException>(
                () => authService.RegisterAsync("attacker_user", "attacker@example.com", weakPassword)
            );
        }

        [Fact]
        public async Task BruteForceProtection_IncorrectPassword_ReturnsNull()
        {
            // Arrange
            var context = CreateInMemoryContext();
            var repository = new UserRepository(context);
            var authService = new AuthenticationService(repository);

            // Create user
            await authService.RegisterAsync("testuser", "test@example.com", "SecurePass123!");

            // Act
            // Attacker tries common passwords
            var result1 = await authService.AuthenticateAsync("testuser", "password123");
            var result2 = await authService.AuthenticateAsync("testuser", "123456");
            var result3 = await authService.AuthenticateAsync("testuser", "admin");

            // Assert
            Assert.Null(result1);
            Assert.Null(result2);
            Assert.Null(result3);
        }

        #endregion

        #region Authorization Attack Scenarios

        [Fact]
        public void UnauthorizedAccessAttack_ElevationOfPrivilege_Blocked()
        {
            // Arrange
            var regularUser = new User
            {
                UserId = 1,
                Username = "user",
                Email = "user@example.com",
                PasswordHash = "hash",
                Role = UserRole.User
            };

            // Act
            // Attacker attempts to access admin resource
            bool canAccess = AuthorizationService.CanAccessResource(regularUser, "admin-dashboard");

            // Assert
            Assert.False(canAccess);
        }

        [Fact]
        public void UnauthorizedActionAttack_AdminAction_Blocked()
        {
            // Arrange
            var regularUser = new User
            {
                UserId = 1,
                Username = "user",
                Email = "user@example.com",
                PasswordHash = "hash",
                Role = UserRole.User
            };

            // Act
            // Attacker attempts admin action
            bool canManageUsers = AuthorizationService.AuthorizeAction(regularUser, "manage-users");

            // Assert
            Assert.False(canManageUsers);
        }

        #endregion

        #region Helper Methods

        private SafeVaultDbContext CreateInMemoryContext()
        {
            var options = new Microsoft.EntityFrameworkCore.DbContextOptionsBuilder<SafeVaultDbContext>()
                .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
                .Options;

            return new SafeVaultDbContext(options);
        }

        #endregion
    }
}
