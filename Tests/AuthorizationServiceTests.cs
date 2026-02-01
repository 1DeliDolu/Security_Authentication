using Xunit;
using SafeVault.Models;
using SafeVault.Services;

namespace SafeVault.Tests
{
    public class AuthorizationServiceTests
    {
        #region Role Checking Tests

        [Fact]
        public void HasRole_AdminUserWithAdminRole_ReturnsTrue()
        {
            // Arrange
            var user = new User
            {
                UserId = 1,
                Username = "admin",
                Email = "admin@example.com",
                PasswordHash = "hash",
                Role = UserRole.Admin
            };

            // Act
            bool result = AuthorizationService.HasRole(user, UserRole.Admin);

            // Assert
            Assert.True(result);
        }

        [Fact]
        public void HasRole_RegularUserWithAdminRole_ReturnsFalse()
        {
            // Arrange
            var user = new User
            {
                UserId = 2,
                Username = "user",
                Email = "user@example.com",
                PasswordHash = "hash",
                Role = UserRole.User
            };

            // Act
            bool result = AuthorizationService.HasRole(user, UserRole.Admin);

            // Assert
            Assert.False(result);
        }

        [Fact]
        public void HasRole_NullUser_ReturnsFalse()
        {
            // Act
            bool result = AuthorizationService.HasRole(null, UserRole.Admin);

            // Assert
            Assert.False(result);
        }

        #endregion

        #region Admin Check Tests

        [Fact]
        public void IsAdmin_AdminUser_ReturnsTrue()
        {
            // Arrange
            var user = new User
            {
                UserId = 1,
                Username = "admin",
                Email = "admin@example.com",
                PasswordHash = "hash",
                Role = UserRole.Admin
            };

            // Act
            bool result = AuthorizationService.IsAdmin(user);

            // Assert
            Assert.True(result);
        }

        [Fact]
        public void IsAdmin_RegularUser_ReturnsFalse()
        {
            // Arrange
            var user = new User
            {
                UserId = 2,
                Username = "user",
                Email = "user@example.com",
                PasswordHash = "hash",
                Role = UserRole.User
            };

            // Act
            bool result = AuthorizationService.IsAdmin(user);

            // Assert
            Assert.False(result);
        }

        [Fact]
        public void IsAdmin_NullUser_ReturnsFalse()
        {
            // Act
            bool result = AuthorizationService.IsAdmin(null);

            // Assert
            Assert.False(result);
        }

        #endregion

        #region Regular User Check Tests

        [Fact]
        public void IsRegularUser_UserWithUserRole_ReturnsTrue()
        {
            // Arrange
            var user = new User
            {
                UserId = 2,
                Username = "user",
                Email = "user@example.com",
                PasswordHash = "hash",
                Role = UserRole.User
            };

            // Act
            bool result = AuthorizationService.IsRegularUser(user);

            // Assert
            Assert.True(result);
        }

        [Fact]
        public void IsRegularUser_AdminUser_ReturnsFalse()
        {
            // Arrange
            var user = new User
            {
                UserId = 1,
                Username = "admin",
                Email = "admin@example.com",
                PasswordHash = "hash",
                Role = UserRole.Admin
            };

            // Act
            bool result = AuthorizationService.IsRegularUser(user);

            // Assert
            Assert.False(result);
        }

        #endregion

        #region Resource Access Tests

        [Theory]
        [InlineData("admin-dashboard")]
        [InlineData("settings")]
        public void CanAccessResource_AdminAccessingAdminResources_ReturnsTrue(string resource)
        {
            // Arrange
            var user = new User
            {
                UserId = 1,
                Username = "admin",
                Email = "admin@example.com",
                PasswordHash = "hash",
                Role = UserRole.Admin
            };

            // Act
            bool result = AuthorizationService.CanAccessResource(user, resource);

            // Assert
            Assert.True(result);
        }

        [Fact]
        public void CanAccessResource_RegularUserAccessingAdminDashboard_ReturnsFalse()
        {
            // Arrange
            var user = new User
            {
                UserId = 2,
                Username = "user",
                Email = "user@example.com",
                PasswordHash = "hash",
                Role = UserRole.User
            };

            // Act
            bool result = AuthorizationService.CanAccessResource(user, "admin-dashboard");

            // Assert
            Assert.False(result);
        }

        [Fact]
        public void CanAccessResource_RegularUserAccessingUserProfile_ReturnsTrue()
        {
            // Arrange
            var user = new User
            {
                UserId = 2,
                Username = "user",
                Email = "user@example.com",
                PasswordHash = "hash",
                Role = UserRole.User
            };

            // Act
            bool result = AuthorizationService.CanAccessResource(user, "user-profile");

            // Assert
            Assert.True(result);
        }

        [Fact]
        public void CanAccessResource_UnknownResource_ReturnsFalse()
        {
            // Arrange
            var user = new User
            {
                UserId = 1,
                Username = "admin",
                Email = "admin@example.com",
                PasswordHash = "hash",
                Role = UserRole.Admin
            };

            // Act
            bool result = AuthorizationService.CanAccessResource(user, "unknown-resource");

            // Assert
            Assert.False(result);
        }

        #endregion

        #region Action Authorization Tests

        [Theory]
        [InlineData("manage-users")]
        [InlineData("view-audit-logs")]
        [InlineData("manage-roles")]
        public void AuthorizeAction_AdminActions_ReturnsTrue(string action)
        {
            // Arrange
            var user = new User
            {
                UserId = 1,
                Username = "admin",
                Email = "admin@example.com",
                PasswordHash = "hash",
                Role = UserRole.Admin
            };

            // Act
            bool result = AuthorizationService.AuthorizeAction(user, action);

            // Assert
            Assert.True(result);
        }

        [Fact]
        public void AuthorizeAction_RegularUserManageUsers_ReturnsFalse()
        {
            // Arrange
            var user = new User
            {
                UserId = 2,
                Username = "user",
                Email = "user@example.com",
                PasswordHash = "hash",
                Role = UserRole.User
            };

            // Act
            bool result = AuthorizationService.AuthorizeAction(user, "manage-users");

            // Assert
            Assert.False(result);
        }

        [Theory]
        [InlineData("view-own-profile")]
        [InlineData("edit-own-profile")]
        [InlineData("delete-own-account")]
        public void AuthorizeAction_UserActions_ReturnsTrue(string action)
        {
            // Arrange
            var user = new User
            {
                UserId = 2,
                Username = "user",
                Email = "user@example.com",
                PasswordHash = "hash",
                Role = UserRole.User
            };

            // Act
            bool result = AuthorizationService.AuthorizeAction(user, action);

            // Assert
            Assert.True(result);
        }

        [Fact]
        public void AuthorizeAction_NullUser_ReturnsFalse()
        {
            // Act
            bool result = AuthorizationService.AuthorizeAction(null, "view-own-profile");

            // Assert
            Assert.False(result);
        }

        #endregion
    }
}
