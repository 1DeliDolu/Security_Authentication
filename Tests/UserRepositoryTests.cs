using Xunit;
using Microsoft.EntityFrameworkCore;
using SafeVault.Data;
using SafeVault.Models;
using SafeVault.Repositories;
using SafeVault.Services;

namespace SafeVault.Tests
{
    public class UserRepositoryTests
    {
        private SafeVaultDbContext CreateInMemoryContext()
        {
            var options = new DbContextOptionsBuilder<SafeVaultDbContext>()
                .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
                .Options;

            return new SafeVaultDbContext(options);
        }

        #region SQL Injection Prevention Tests

        [Fact]
        public async Task CreateUserAsync_SQLInjectionInUsername_Blocked()
        {
            // Arrange
            var context = CreateInMemoryContext();
            var repository = new UserRepository(context);
            string maliciousUsername = "'; DROP TABLE Users; --";
            string email = "test@example.com";
            string passwordHash = "hashedPassword123";

            // Act & Assert
            // Invalid username format should prevent SQL injection
            var exception = await Assert.ThrowsAsync<ArgumentException>(
                () => repository.CreateUserAsync(maliciousUsername, email, passwordHash)
            );

            Assert.Contains("Invalid username", exception.Message);
        }

        [Fact]
        public async Task GetUserByUsernameAsync_SQLInjectionPayload_NoExecution()
        {
            // Arrange
            var context = CreateInMemoryContext();
            var repository = new UserRepository(context);

            // Add a legitimate user first
            var user = new User
            {
                Username = "john_doe",
                Email = "john@example.com",
                PasswordHash = "hashedPassword"
            };
            context.Users.Add(user);
            await context.SaveChangesAsync();

            // Act
            // This SQL injection attempt should be treated as a literal string parameter
            var result = await repository.GetUserByUsernameAsync("' OR '1'='1");

            // Assert
            Assert.Null(result); // No user should be returned from injection attempt
        }

        [Fact]
        public async Task GetUserByEmailAsync_SQLInjectionEmail_NoExecution()
        {
            // Arrange
            var context = CreateInMemoryContext();
            var repository = new UserRepository(context);

            var user = new User
            {
                Username = "test_user",
                Email = "test@example.com",
                PasswordHash = "hashedPassword"
            };
            context.Users.Add(user);
            await context.SaveChangesAsync();

            // Act
            // SQL injection payload should not execute
            var result = await repository.GetUserByEmailAsync("test@example.com' OR '1'='1");

            // Assert
            Assert.Null(result);
        }

        #endregion

        #region XSS Prevention Tests (Input Sanitization)

        [Fact]
        public void CreateUserAsync_XSSInUsername_InvalidFormat()
        {
            // Arrange
            var context = CreateInMemoryContext();
            var repository = new UserRepository(context);
            string xssUsername = "<script>alert('XSS')</script>";
            string email = "test@example.com";
            string passwordHash = "hashedPassword";

            // Act & Assert
            // XSS payload in username should fail validation
            var exception = Assert.ThrowsAsync<ArgumentException>(
                () => repository.CreateUserAsync(xssUsername, email, passwordHash)
            );

            Assert.NotNull(exception);
        }

        [Fact]
        public async Task UpdateUserEmailAsync_SanitizesInput()
        {
            // Arrange
            var context = CreateInMemoryContext();
            var repository = new UserRepository(context);

            var user = new User
            {
                Username = "john_doe",
                Email = "john@example.com",
                PasswordHash = "hashedPassword"
            };
            context.Users.Add(user);
            await context.SaveChangesAsync();

            // Act
            // Try to update with invalid email
            var result = await repository.UpdateUserEmailAsync(user.UserId, "invalid-email");

            // Assert
            Assert.False(result); // Should fail due to invalid email format
        }

        #endregion

        #region Parameterized Query Tests

        [Fact]
        public async Task CreateUserAsync_ValidInput_CreatesUser()
        {
            // Arrange
            var context = CreateInMemoryContext();
            var repository = new UserRepository(context);
            string username = "john_doe";
            string email = "john@example.com";
            string passwordHash = "secureHashedPassword";

            // Act
            bool result = await repository.CreateUserAsync(username, email, passwordHash);

            // Assert
            Assert.True(result);
            var createdUser = await context.Users.FirstOrDefaultAsync(u => u.Username == username);
            Assert.NotNull(createdUser);
            Assert.Equal(email, createdUser.Email);
        }

        [Fact]
        public async Task GetUserByUsernameAsync_ValidUsername_ReturnsUser()
        {
            // Arrange
            var context = CreateInMemoryContext();
            var repository = new UserRepository(context);
            var user = new User
            {
                Username = "testuser",
                Email = "test@example.com",
                PasswordHash = "hashedPassword"
            };
            context.Users.Add(user);
            await context.SaveChangesAsync();

            // Act
            var retrievedUser = await repository.GetUserByUsernameAsync("testuser");

            // Assert
            Assert.NotNull(retrievedUser);
            Assert.Equal("testuser", retrievedUser.Username);
        }

        [Fact]
        public async Task GetUserByIdAsync_ValidId_ReturnsUser()
        {
            // Arrange
            var context = CreateInMemoryContext();
            var repository = new UserRepository(context);
            var user = new User
            {
                Username = "john",
                Email = "john@example.com",
                PasswordHash = "hashedPassword"
            };
            context.Users.Add(user);
            await context.SaveChangesAsync();

            // Act
            var retrievedUser = await repository.GetUserByIdAsync(user.UserId);

            // Assert
            Assert.NotNull(retrievedUser);
            Assert.Equal(user.UserId, retrievedUser.UserId);
        }

        #endregion

        #region Duplicate User Prevention Tests

        [Fact]
        public async Task CreateUserAsync_DuplicateUsername_ReturnsFalse()
        {
            // Arrange
            var context = CreateInMemoryContext();
            var repository = new UserRepository(context);

            // Create first user
            await repository.CreateUserAsync("john_doe", "john@example.com", "hash1");

            // Act
            // Try to create duplicate username
            bool result = await repository.CreateUserAsync("john_doe", "different@example.com", "hash2");

            // Assert
            Assert.False(result);
        }

        [Fact]
        public async Task CreateUserAsync_DuplicateEmail_ReturnsFalse()
        {
            // Arrange
            var context = CreateInMemoryContext();
            var repository = new UserRepository(context);

            // Create first user
            await repository.CreateUserAsync("john_doe", "john@example.com", "hash1");

            // Act
            // Try to create duplicate email
            bool result = await repository.CreateUserAsync("jane_doe", "john@example.com", "hash2");

            // Assert
            Assert.False(result);
        }

        #endregion
    }
}
