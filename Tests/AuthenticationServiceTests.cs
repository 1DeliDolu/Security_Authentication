using Xunit;
using SafeVault.Models;
using SafeVault.Services;

namespace SafeVault.Tests
{
    public class AuthenticationServiceTests
    {
        #region Password Hashing & Verification Tests

        [Fact]
        public void HashPassword_CreatesValidHash()
        {
            // Arrange
            string password = "SecurePassword123!";

            // Act
            string hash = AuthenticationService.HashPassword(password);

            // Assert
            Assert.NotNull(hash);
            Assert.NotEmpty(hash);
            Assert.NotEqual(password, hash);
        }

        [Fact]
        public void HashPassword_SamePasswordProducesDifferentHashes()
        {
            // Arrange
            string password = "SecurePassword123!";

            // Act
            string hash1 = AuthenticationService.HashPassword(password);
            string hash2 = AuthenticationService.HashPassword(password);

            // Assert
            // Hashes should be different due to random salt
            Assert.NotEqual(hash1, hash2);
        }

        [Fact]
        public void VerifyPassword_CorrectPassword_ReturnsTrue()
        {
            // Arrange
            string password = "SecurePassword123!";
            string hash = AuthenticationService.HashPassword(password);

            // Act
            bool result = AuthenticationService.VerifyPassword(password, hash);

            // Assert
            Assert.True(result);
        }

        [Fact]
        public void VerifyPassword_IncorrectPassword_ReturnsFalse()
        {
            // Arrange
            string password = "SecurePassword123!";
            string wrongPassword = "WrongPassword123!";
            string hash = AuthenticationService.HashPassword(password);

            // Act
            bool result = AuthenticationService.VerifyPassword(wrongPassword, hash);

            // Assert
            Assert.False(result);
        }

        [Fact]
        public void VerifyPassword_InvalidHash_ReturnsFalse()
        {
            // Arrange
            string password = "SecurePassword123!";
            string invalidHash = "invalid-base64-hash!@#$%";

            // Act
            bool result = AuthenticationService.VerifyPassword(password, invalidHash);

            // Assert
            Assert.False(result);
        }

        #endregion

        #region Authentication Tests

        [Fact]
        public async Task AuthenticateAsync_ValidCredentials_ReturnsUser()
        {
            // Arrange
            var context = CreateInMemoryContext();
            var repository = new UserRepository(context);
            var authService = new AuthenticationService(repository);

            // Create and register user
            string username = "testuser";
            string email = "test@example.com";
            string password = "SecurePassword123!";

            await authService.RegisterAsync(username, email, password);

            // Act
            var result = await authService.AuthenticateAsync(username, password);

            // Assert
            Assert.NotNull(result);
            Assert.Equal(username, result.Username);
            Assert.Equal(email, result.Email);
        }

        [Fact]
        public async Task AuthenticateAsync_InvalidPassword_ReturnsNull()
        {
            // Arrange
            var context = CreateInMemoryContext();
            var repository = new UserRepository(context);
            var authService = new AuthenticationService(repository);

            string username = "testuser";
            string email = "test@example.com";
            string password = "SecurePassword123!";

            await authService.RegisterAsync(username, email, password);

            // Act
            var result = await authService.AuthenticateAsync(username, "WrongPassword123!");

            // Assert
            Assert.Null(result);
        }

        [Fact]
        public async Task AuthenticateAsync_NonexistentUser_ReturnsNull()
        {
            // Arrange
            var context = CreateInMemoryContext();
            var repository = new UserRepository(context);
            var authService = new AuthenticationService(repository);

            // Act
            var result = await authService.AuthenticateAsync("nonexistent", "password123");

            // Assert
            Assert.Null(result);
        }

        [Fact]
        public async Task AuthenticateAsync_InvalidUsername_ReturnsNull()
        {
            // Arrange
            var context = CreateInMemoryContext();
            var repository = new UserRepository(context);
            var authService = new AuthenticationService(repository);

            // Act
            var result = await authService.AuthenticateAsync("invalid@user!", "password123");

            // Assert
            Assert.Null(result);
        }

        #endregion

        #region Registration Tests

        [Fact]
        public async Task RegisterAsync_ValidData_CreatesUser()
        {
            // Arrange
            var context = CreateInMemoryContext();
            var repository = new UserRepository(context);
            var authService = new AuthenticationService(repository);

            string username = "newuser";
            string email = "new@example.com";
            string password = "SecurePassword123!";

            // Act
            bool result = await authService.RegisterAsync(username, email, password);

            // Assert
            Assert.True(result);
        }

        [Fact]
        public async Task RegisterAsync_WeakPassword_ThrowsException()
        {
            // Arrange
            var context = CreateInMemoryContext();
            var repository = new UserRepository(context);
            var authService = new AuthenticationService(repository);

            string username = "newuser";
            string email = "new@example.com";
            string weakPassword = "weak"; // Fails password strength validation

            // Act & Assert
            await Assert.ThrowsAsync<ArgumentException>(
                () => authService.RegisterAsync(username, email, weakPassword)
            );
        }

        [Fact]
        public async Task RegisterAsync_InvalidEmail_ThrowsException()
        {
            // Arrange
            var context = CreateInMemoryContext();
            var repository = new UserRepository(context);
            var authService = new AuthenticationService(repository);

            string username = "newuser";
            string invalidEmail = "not-an-email";
            string password = "SecurePassword123!";

            // Act & Assert
            await Assert.ThrowsAsync<ArgumentException>(
                () => authService.RegisterAsync(username, invalidEmail, password)
            );
        }

        #endregion

        private SafeVaultDbContext CreateInMemoryContext()
        {
            var options = new Microsoft.EntityFrameworkCore.DbContextOptionsBuilder<SafeVaultDbContext>()
                .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
                .Options;

            return new SafeVaultDbContext(options);
        }
    }
}
