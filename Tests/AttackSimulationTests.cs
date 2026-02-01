using Microsoft.EntityFrameworkCore;
using NUnit.Framework;
using SafeVault.Data;
using SafeVault.Repositories;
using SafeVault.Services;

namespace SafeVault.Tests;

[TestFixture]
public class AttackSimulationTests
{
    private static SafeVaultDbContext CreateContext()
    {
        var options = new DbContextOptionsBuilder<SafeVaultDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;

        return new SafeVaultDbContext(options);
    }

    [TestCase("' OR '1'='1")]
    [TestCase("'; DROP TABLE Users; --")]
    [TestCase("' UNION SELECT * FROM Users --")]
    [TestCase("admin'--")]
    [TestCase("'; WAITFOR DELAY '0:0:5' --")]
    public async Task SqlInjection_Attempts_DoNotAuthenticate(string payload)
    {
        await using var context = CreateContext();
        var repo = new UserRepository(context);
        var auth = new AuthenticationService(repo);

        await auth.RegisterAsync("john_doe", "john@example.com", "SecurePass123!");

        var user = await auth.AuthenticateAsync(payload, "anything");

        Assert.That(user, Is.Null);
    }

    [TestCase("<script>alert('XSS')</script>")]
    [TestCase("<img src=x onerror='alert(1)'>")]
    [TestCase("<svg onload='alert(1)'></svg>")]
    [TestCase("<iframe src='javascript:alert(1)'></iframe>")]
    public void XssPayloads_AreEncoded(string payload)
    {
        var encoded = InputValidationService.SanitizeHtml(payload);

        Assert.That(encoded, Does.Not.Contain("<"));
        Assert.That(encoded, Does.Not.Contain(">"));
    }

    [Test]
    public async Task CombinedAttack_SqlInjectionWithXss_Blocked()
    {
        await using var context = CreateContext();
        var repo = new UserRepository(context);
        var auth = new AuthenticationService(repo);

        await auth.RegisterAsync("john_doe", "john@example.com", "SecurePass123!");

        var payload = "' OR '1'='1<script>alert(1)</script>";
        var user = await auth.AuthenticateAsync(payload, "anything");

        Assert.That(user, Is.Null);
        Assert.That(InputValidationService.ValidateUsername(payload), Is.False);
    }
}
