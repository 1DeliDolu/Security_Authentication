using NUnit.Framework;
using SafeVault.Models;
using SafeVault.Services;

namespace SafeVault.Tests;

[TestFixture]
public class AuthorizationServiceTests
{
    private static User CreateUser(UserRole role)
    {
        return new User
        {
            Username = "jane_doe",
            Email = "jane@example.com",
            Role = role,
        };
    }

    [Test]
    public void IsAdmin_ReturnsTrueForAdmin()
    {
        var admin = CreateUser(UserRole.Admin);

        Assert.That(AuthorizationService.IsAdmin(admin), Is.True);
    }

    [Test]
    public void IsAdmin_ReturnsFalseForUser()
    {
        var user = CreateUser(UserRole.User);

        Assert.That(AuthorizationService.IsAdmin(user), Is.False);
    }

    [Test]
    public void CanAccessResource_AdminDashboard_AllowsAdmin()
    {
        var admin = CreateUser(UserRole.Admin);

        Assert.That(AuthorizationService.CanAccessResource(admin, "admin-dashboard"), Is.True);
    }

    [Test]
    public void CanAccessResource_AdminDashboard_DeniesUser()
    {
        var user = CreateUser(UserRole.User);

        Assert.That(AuthorizationService.CanAccessResource(user, "admin-dashboard"), Is.False);
    }

    [Test]
    public void CanAccessResource_UserProfile_AllowsUser()
    {
        var user = CreateUser(UserRole.User);

        Assert.That(AuthorizationService.CanAccessResource(user, "user-profile"), Is.True);
    }

    [Test]
    public void CanAccessResource_UserProfile_AllowsAdmin()
    {
        var admin = CreateUser(UserRole.Admin);

        Assert.That(AuthorizationService.CanAccessResource(admin, "user-profile"), Is.True);
    }

    [Test]
    public void CanAccessResource_NullUser_DeniesAccess()
    {
        Assert.That(AuthorizationService.CanAccessResource(null, "admin-dashboard"), Is.False);
    }

    [Test]
    public void AuthorizeAction_ManageUsers_AllowsAdmin()
    {
        var admin = CreateUser(UserRole.Admin);

        Assert.That(AuthorizationService.AuthorizeAction(admin, "manage-users"), Is.True);
    }

    [Test]
    public void AuthorizeAction_ManageUsers_DeniesUser()
    {
        var user = CreateUser(UserRole.User);

        Assert.That(AuthorizationService.AuthorizeAction(user, "manage-users"), Is.False);
    }

    [Test]
    public void AuthorizeAction_EditOwnProfile_AllowsUser()
    {
        var user = CreateUser(UserRole.User);

        Assert.That(AuthorizationService.AuthorizeAction(user, "edit-own-profile"), Is.True);
    }

    [Test]
    public void AuthorizeAction_EditOwnProfile_AllowsAdmin()
    {
        var admin = CreateUser(UserRole.Admin);

        Assert.That(AuthorizationService.AuthorizeAction(admin, "edit-own-profile"), Is.True);
    }

    [Test]
    public void AuthorizeAction_UnknownAction_DeniesAccess()
    {
        var admin = CreateUser(UserRole.Admin);

        Assert.That(AuthorizationService.AuthorizeAction(admin, "unknown-action"), Is.False);
    }
}
