using NUnit.Framework;
using SafeVault.Services;

namespace SafeVault.Tests;

[TestFixture]
public class InputValidationServiceTests
{
    [TestCase("john_doe", true)]
    [TestCase("ab", false)]
    [TestCase("john@doe", false)]
    [TestCase("john doe", false)]
    [TestCase("john_doe123", true)]
    public void ValidateUsername_Works(string username, bool expected)
    {
        Assert.That(InputValidationService.ValidateUsername(username), Is.EqualTo(expected));
    }

    [TestCase("john@example.com", true)]
    [TestCase("not-an-email", false)]
    [TestCase("john@bad domain.com", false)]
    [TestCase("<script>@example.com", false)]
    public void ValidateEmail_Works(string email, bool expected)
    {
        Assert.That(InputValidationService.ValidateEmail(email), Is.EqualTo(expected));
    }

    [TestCase("SecurePass123!", true)]
    [TestCase("short1!", false)]
    [TestCase("nouppercase1!", false)]
    [TestCase("NOLOWERCASE1!", false)]
    [TestCase("NoSpecial123", false)]
    public void ValidatePassword_Works(string password, bool expected)
    {
        Assert.That(InputValidationService.ValidatePassword(password), Is.EqualTo(expected));
    }

    [Test]
    public void SanitizeHtml_EncodesScript()
    {
        var input = "<script>alert('XSS')</script>";
        var encoded = InputValidationService.SanitizeHtml(input);

        Assert.That(encoded, Is.EqualTo("&lt;script&gt;alert(&#39;XSS&#39;)&lt;/script&gt;"));
    }

    [Test]
    public void SanitizeHtml_EncodesImageOnError()
    {
        var input = "<img src=x onerror='alert(1)'>";
        var encoded = InputValidationService.SanitizeHtml(input);

        Assert.That(encoded, Does.Contain("&lt;img"));
        Assert.That(encoded, Does.Contain("onerror"));
        Assert.That(encoded, Does.Not.Contain("<img"));
    }
}
