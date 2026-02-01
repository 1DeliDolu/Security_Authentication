using System.Text.RegularExpressions;

namespace SafeVault.Services
{
    /// <summary>
    /// Provides secure input validation and sanitization to prevent XSS attacks.
    /// </summary>
    public class InputValidationService
    {
        /// <summary>
        /// Validates username: alphanumeric + underscore, 3-50 chars
        /// </summary>
        public static bool ValidateUsername(string? username)
        {
            if (string.IsNullOrWhiteSpace(username))
                return false;

            if (username.Length < 3 || username.Length > 50)
                return false;

            // Allow only alphanumeric and underscore
            return Regex.IsMatch(username, @"^[a-zA-Z0-9_]+$");
        }

        /// <summary>
        /// Validates email format
        /// </summary>
        public static bool ValidateEmail(string? email)
        {
            if (string.IsNullOrWhiteSpace(email))
                return false;

            try
            {
                var addr = new System.Net.Mail.MailAddress(email);
                return addr.Address == email && email.Length <= 100;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Sanitizes HTML input to prevent XSS attacks by escaping dangerous characters
        /// </summary>
        public static string SanitizeHtml(string? input)
        {
            if (string.IsNullOrEmpty(input))
                return string.Empty;

            return System.Net.WebUtility.HtmlEncode(input);
        }

        /// <summary>
        /// Validates password strength: min 8 chars, at least 1 uppercase, 1 lowercase, 1 digit, 1 special
        /// </summary>
        public static bool ValidatePasswordStrength(string? password)
        {
            if (string.IsNullOrWhiteSpace(password))
                return false;

            if (password.Length < 8)
                return false;

            bool hasUpperCase = Regex.IsMatch(password, @"[A-Z]");
            bool hasLowerCase = Regex.IsMatch(password, @"[a-z]");
            bool hasDigit = Regex.IsMatch(password, @"[\d]");
            bool hasSpecialChar = Regex.IsMatch(password, @"[!@#$%^&*()_+\-=\[\]{};':""\|,.<>\/?]");

            return hasUpperCase && hasLowerCase && hasDigit && hasSpecialChar;
        }
    }
}
