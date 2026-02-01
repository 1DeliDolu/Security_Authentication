using Microsoft.EntityFrameworkCore;
using NUnit.Framework;
using SafeVault.Data;
using SafeVault.Repositories;
using SafeVault.Services;

namespace SafeVault.Tests;

[TestFixture]
public class AuthenticationServiceTests
{
    private static SafeVaultDbContext CreateContext()
    {
        var options = new DbContextOptionsBuilder<SafeVaultDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;

        return new SafeVaultDbContext(options);
    }

    [Test]
    public void HashPassword_UsesUniqueSalt()
    {
        var hash1 = AuthenticationService.HashPassword("SecurePass123!");
        var hash2 = AuthenticationService.HashPassword("SecurePass123!");

        Assert.That(hash1, Is.Not.EqualTo(hash2));
    }

    [Test]
    public void VerifyPassword_ReturnsTrueForCorrectPassword()
    {
        var hash = AuthenticationService.HashPassword("SecurePass123!");

        Assert.That(AuthenticationService.VerifyPassword("SecurePass123!", hash), Is.True);
    }

    [Test]
    public void VerifyPassword_ReturnsFalseForWrongPassword()
    {
        var hash = AuthenticationService.HashPassword("SecurePass123!");

        Assert.That(AuthenticationService.VerifyPassword("WrongPass123!", hash), Is.False);
    }

    [Test]
    public async Task RegisterAsync_CreatesUserWithHashedPassword()
    {
        await using var context = CreateContext();
        var repo = new UserRepository(context);
        var auth = new AuthenticationService(repo);

        var result = await auth.RegisterAsync("john_doe", "john@example.com", "SecurePass123!");
        Assert.That(result, Is.True);

        var user = await repo.GetByUsernameAsync("john_doe");
        Assert.That(user, Is.Not.Null);
        Assert.That(user!.PasswordHash, Is.Not.Empty);
        Assert.That(user.PasswordHash, Is.Not.EqualTo("SecurePass123!"));
        Assert.That(user.Role.ToString(), Is.EqualTo("User"));
    }

    [Test]
    public void RegisterAsync_RejectsInvalidUsername()
    {
        using var context = CreateContext();
        var repo = new UserRepository(context);
        var auth = new AuthenticationService(repo);

        Assert.That(
            async () => await auth.RegisterAsync("ab", "john@example.com", "SecurePass123!"),
            Throws.TypeOf<ArgumentException>()
        );
    }

    [Test]
    public void RegisterAsync_RejectsInvalidEmail()
    {
        using var context = CreateContext();
        var repo = new UserRepository(context);
        var auth = new AuthenticationService(repo);

        Assert.That(
            async () => await auth.RegisterAsync("john_doe", "bad-email", "SecurePass123!"),
            Throws.TypeOf<ArgumentException>()
        );
    }

    [Test]
    public void RegisterAsync_RejectsWeakPassword()
    {
        using var context = CreateContext();
        var repo = new UserRepository(context);
        var auth = new AuthenticationService(repo);

        Assert.That(
            async () => await auth.RegisterAsync("john_doe", "john@example.com", "weak"),
            Throws.TypeOf<ArgumentException>()
        );
    }

    [Test]
    public async Task RegisterAsync_RejectsDuplicateUsername()
    {
        await using var context = CreateContext();
        var repo = new UserRepository(context);
        var auth = new AuthenticationService(repo);

        await auth.RegisterAsync("john_doe", "john@example.com", "SecurePass123!");

        Assert.That(
            async () => await auth.RegisterAsync("john_doe", "john2@example.com", "SecurePass123!"),
            Throws.TypeOf<InvalidOperationException>()
        );
    }

    [Test]
    public async Task RegisterAsync_RejectsDuplicateEmail()
    {
        await using var context = CreateContext();
        var repo = new UserRepository(context);
        var auth = new AuthenticationService(repo);

        await auth.RegisterAsync("john_doe", "john@example.com", "SecurePass123!");

        Assert.That(
            async () => await auth.RegisterAsync("john2", "john@example.com", "SecurePass123!"),
            Throws.TypeOf<InvalidOperationException>()
        );
    }

    [Test]
    public async Task AuthenticateAsync_ReturnsNullForUnknownUser()
    {
        await using var context = CreateContext();
        var repo = new UserRepository(context);
        var auth = new AuthenticationService(repo);

        var user = await auth.AuthenticateAsync("missing", "SecurePass123!");

        Assert.That(user, Is.Null);
    }

    [Test]
    public async Task AuthenticateAsync_ReturnsNullForWrongPassword()
    {
        await using var context = CreateContext();
        var repo = new UserRepository(context);
        var auth = new AuthenticationService(repo);

        await auth.RegisterAsync("john_doe", "john@example.com", "SecurePass123!");

        var user = await auth.AuthenticateAsync("john_doe", "WrongPass123!");

        Assert.That(user, Is.Null);
    }

    [Test]
    public async Task AuthenticateAsync_UpdatesLastLoginAt()
    {
        await using var context = CreateContext();
        var repo = new UserRepository(context);
        var auth = new AuthenticationService(repo);

        await auth.RegisterAsync("john_doe", "john@example.com", "SecurePass123!");

        var before = DateTime.UtcNow;
        var user = await auth.AuthenticateAsync("john_doe", "SecurePass123!");

        Assert.That(user, Is.Not.Null);
        Assert.That(user!.LastLoginAt, Is.Not.Null);
        Assert.That(user.LastLoginAt, Is.GreaterThanOrEqualTo(before));
    }
}
