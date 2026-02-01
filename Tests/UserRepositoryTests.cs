using Microsoft.EntityFrameworkCore;
using NUnit.Framework;
using SafeVault.Data;
using SafeVault.Models;
using SafeVault.Repositories;
using SafeVault.Services;

namespace SafeVault.Tests;

[TestFixture]
public class UserRepositoryTests
{
    private static SafeVaultDbContext CreateContext()
    {
        var options = new DbContextOptionsBuilder<SafeVaultDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;

        return new SafeVaultDbContext(options);
    }

    [Test]
    public async Task CreateUserAsync_InsertsUser()
    {
        await using var context = CreateContext();
        var repo = new UserRepository(context);
        var hash = AuthenticationService.HashPassword("SecurePass123!");

        var user = await repo.CreateUserAsync(
            new User
            {
                Username = "john_doe",
                Email = "john@example.com",
                PasswordHash = hash,
                Role = UserRole.User
            }
        );

        Assert.That(user.UserId, Is.GreaterThan(0));
        var fetched = await repo.GetByUsernameAsync("john_doe");
        Assert.That(fetched, Is.Not.Null);
        Assert.That(fetched!.Email, Is.EqualTo("john@example.com"));
    }

    [Test]
    public async Task CreateUserAsync_RejectsDuplicateUser()
    {
        await using var context = CreateContext();
        var repo = new UserRepository(context);
        var hash = AuthenticationService.HashPassword("SecurePass123!");

        await repo.CreateUserAsync(
            new User
            {
                Username = "john_doe",
                Email = "john@example.com",
                PasswordHash = hash,
                Role = UserRole.User
            }
        );

        Assert.That(
            async () =>
                await repo.CreateUserAsync(
                    new User
                    {
                        Username = "john_doe",
                        Email = "john2@example.com",
                        PasswordHash = hash,
                        Role = UserRole.User
                    }
                ),
            Throws.TypeOf<InvalidOperationException>()
        );
    }

    [Test]
    public async Task GetByUsernameAsync_DoesNotAllowSqlInjection()
    {
        await using var context = CreateContext();
        var repo = new UserRepository(context);
        var hash = AuthenticationService.HashPassword("SecurePass123!");

        await repo.CreateUserAsync(
            new User
            {
                Username = "john_doe",
                Email = "john@example.com",
                PasswordHash = hash,
                Role = UserRole.User
            }
        );

        var result = await repo.GetByUsernameAsync("' OR '1'='1");

        Assert.That(result, Is.Null);
    }

    [Test]
    public async Task CreateUserAsync_RejectsXssPayloadInUsername()
    {
        await using var context = CreateContext();
        var repo = new UserRepository(context);
        var hash = AuthenticationService.HashPassword("SecurePass123!");

        Assert.That(
            async () =>
                await repo.CreateUserAsync(
                    new User
                    {
                        Username = "<script>alert(1)</script>",
                        Email = "xss@example.com",
                        PasswordHash = hash,
                        Role = UserRole.User
                    }
                ),
            Throws.TypeOf<ArgumentException>()
        );
    }
}
