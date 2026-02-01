using Xunit;
using SafeVault.Services;

namespace SafeVault.Tests
{
    public class InputValidationServiceTests
    {
        #region Username Validation Tests

        [Fact]
        public void ValidateUsername_ValidUsername_ReturnsTrue()
        {
            // Arrange
            string validUsername = "john_doe123";

            // Act
            bool result = InputValidationService.ValidateUsername(validUsername);

            // Assert
            Assert.True(result);
        }

        [Theory]
        [InlineData("ab")]          // Too short
        [InlineData("")]            // Empty
        [InlineData(null)]          // Null
        [InlineData("john@doe")]    // Special char (not underscore)
        [InlineData("john doe")]    // Space
        public void ValidateUsername_InvalidUsername_ReturnsFalse(string? username)
        {
            // Act
            bool result = InputValidationService.ValidateUsername(username);

            // Assert
            Assert.False(result);
        }

        #endregion

        #region Email Validation Tests

        [Theory]
        [InlineData("user@example.com")]
        [InlineData("test123@domain.co.uk")]
        public void ValidateEmail_ValidEmail_ReturnsTrue(string email)
        {
            // Act
            bool result = InputValidationService.ValidateEmail(email);

            // Assert
            Assert.True(result);
        }

        [Theory]
        [InlineData("invalid.email")]
        [InlineData("user@")]
        [InlineData("@example.com")]
        [InlineData("")]
        public void ValidateEmail_InvalidEmail_ReturnsFalse(string email)
        {
            // Act
            bool result = InputValidationService.ValidateEmail(email);

            // Assert
            Assert.False(result);
        }

        #endregion

        #region HTML Sanitization Tests (XSS Prevention)

        [Fact]
        public void SanitizeHtml_ScriptTag_Escapes()
        {
            // Arrange
            string input = "<script>alert('XSS')</script>";
            string expected = "&lt;script&gt;alert(&#39;XSS&#39;)&lt;/script&gt;";

            // Act
            string result = InputValidationService.SanitizeHtml(input);

            // Assert
            Assert.Equal(expected, result);
        }

        [Fact]
        public void SanitizeHtml_EventHandler_Escapes()
        {
            // Arrange
            string input = "<img src=x onerror='alert(\"XSS\")'>";
            
            // Act
            string result = InputValidationService.SanitizeHtml(input);

            // Assert
            // Should escape dangerous characters
            Assert.DoesNotContain("onerror=", result);
            Assert.Contains("&lt;", result);
        }

        [Fact]
        public void SanitizeHtml_Null_ReturnsEmpty()
        {
            // Act
            string result = InputValidationService.SanitizeHtml(null);

            // Assert
            Assert.Equal(string.Empty, result);
        }

        #endregion

        #region Password Strength Tests

        [Fact]
        public void ValidatePasswordStrength_StrongPassword_ReturnsTrue()
        {
            // Arrange
            string strongPassword = "SecurePass123!";

            // Act
            bool result = InputValidationService.ValidatePasswordStrength(strongPassword);

            // Assert
            Assert.True(result);
        }

        [Theory]
        [InlineData("weak")]                    // Too short, no uppercase/special
        [InlineData("NoDigit!@#")]              // No digit
        [InlineData("NOLOWERCASE123!")]         // No lowercase
        [InlineData("Nospecial123")]            // No special char
        public void ValidatePasswordStrength_WeakPassword_ReturnsFalse(string password)
        {
            // Act
            bool result = InputValidationService.ValidatePasswordStrength(password);

            // Assert
            Assert.False(result);
        }

        #endregion

        #region XSS Attack Simulation Tests

        [Theory]
        [InlineData("<img src=x onerror='alert(\"XSS\")'>")]
        [InlineData("<iframe src='javascript:alert(1)'></iframe>")]
        [InlineData("<svg onload='alert(1)'>")]
        public void SanitizeHtml_CommonXSSPatterns_Escapes(string xssPayload)
        {
            // Act
            string result = InputValidationService.SanitizeHtml(xssPayload);

            // Assert
            // Result should be escaped, not contain raw HTML tags
            Assert.DoesNotContain("<img", result);
            Assert.DoesNotContain("<iframe", result);
            Assert.DoesNotContain("<svg", result);
        }

        #endregion
    }
}
