using System.Net;
using System.Text.RegularExpressions;

namespace SafeVault.Services;

public static class InputValidationService
{
    private static readonly Regex UsernameRegex = new(
        @"^[a-zA-Z0-9_]{3,50}$",
        RegexOptions.Compiled
    );
    private static readonly Regex EmailRegex = new(
        @"^[^@\s]+@[^@\s]+\.[^@\s]+$",
        RegexOptions.Compiled
    );
    private static readonly Regex PasswordRegex = new(
        @"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,}$",
        RegexOptions.Compiled
    );
    private static readonly char[] EmailDisallowedChars = { '<', '>', '"', '\'' };

    public static bool ValidateUsername(string? username)
    {
        if (string.IsNullOrWhiteSpace(username))
        {
            return false;
        }

        return UsernameRegex.IsMatch(username);
    }

    public static bool ValidateEmail(string? email)
    {
        if (string.IsNullOrWhiteSpace(email))
        {
            return false;
        }

        if (email.Length > 100)
        {
            return false;
        }

        if (email.IndexOfAny(EmailDisallowedChars) >= 0)
        {
            return false;
        }

        return EmailRegex.IsMatch(email);
    }

    public static bool ValidatePassword(string? password)
    {
        if (string.IsNullOrWhiteSpace(password))
        {
            return false;
        }

        return PasswordRegex.IsMatch(password);
    }

    public static string SanitizeHtml(string? input)
    {
        if (string.IsNullOrEmpty(input))
        {
            return string.Empty;
        }

        return WebUtility.HtmlEncode(input);
    }

    public static string Normalize(string input)
    {
        return input.Trim();
    }
}
