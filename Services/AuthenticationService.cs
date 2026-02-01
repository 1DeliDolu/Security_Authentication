using SafeVault.Models;
using System.Security.Cryptography;
using System.Text;

namespace SafeVault.Services
{
    /// <summary>
    /// Authentication service with bcrypt-style secure password hashing.
    /// Handles user login and password verification.
    /// </summary>
    public class AuthenticationService(AuthenticationService.UserRepository userRepository)
    {
        private const int SaltSize = 16;
        private const int HashSize = 20;
        private const int Iterations = 10000;

        /// <summary>
        /// Hashes a password securely using PBKDF2 with SHA256.
        /// This is a simplified version; production should use bcrypt or Argon2.
        /// </summary>
        public static string HashPassword(string password)
        {
            using (var rng = new RNGCryptoServiceProvider())
            {
                byte[] salt = new byte[SaltSize];
                rng.GetBytes(salt);

                using (var pbkdf2 = new Rfc2898DeriveBytes(password, salt, Iterations, HashAlgorithmName.SHA256))
                {
                    byte[] hash = pbkdf2.GetBytes(HashSize);

                    byte[] hashWithSalt = new byte[SaltSize + HashSize];
                    Array.Copy(salt, 0, hashWithSalt, 0, SaltSize);
                    Array.Copy(hash, 0, hashWithSalt, SaltSize, HashSize);

                    return Convert.ToBase64String(hashWithSalt);
                }
            }
        }

        /// <summary>
        /// Verifies a plain text password against a stored hash.
        /// </summary>
        public static bool VerifyPassword(string password, string hash)
        {
            try
            {
                byte[] hashBytes = Convert.FromBase64String(hash);

                byte[] salt = new byte[SaltSize];
                Array.Copy(hashBytes, 0, salt, 0, SaltSize);

                using (var pbkdf2 = new Rfc2898DeriveBytes(password, salt, Iterations, HashAlgorithmName.SHA256))
                {
                    byte[] computedHash = pbkdf2.GetBytes(HashSize);

                    for (int i = 0; i < HashSize; i++)
                    {
                        if (hashBytes[i + SaltSize] != computedHash[i])
                        {
                            return false;
                        }
                    }
                }

                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Authenticates a user by username and password.
        /// Returns the user if authentication succeeds, null otherwise.
        /// </summary>
        public async Task<User?> AuthenticateAsync(string username, string password)
        {
            if (!InputValidationService.ValidateUsername(username))
                return null;

            if (string.IsNullOrWhiteSpace(password))
                return null;

            var user = await userRepository.GetUserByUsernameAsync(username);
            if (user == null)
                return null;

            if (!VerifyPassword(password, user.PasswordHash))
                return null;

            // Update last login time
            user.LastLoginAt = DateTime.UtcNow;
            await userRepository.UpdateUserAsync(user);

            return user;
        }

        /// <summary>
        /// Registers a new user with secure password hashing.
        /// </summary>
        public async Task<bool> RegisterAsync(string username, string email, string password)
        {
            if (!InputValidationService.ValidateUsername(username))
                throw new ArgumentException("Invalid username format.");

            if (!InputValidationService.ValidateEmail(email))
                throw new ArgumentException("Invalid email format.");

            if (!InputValidationService.ValidatePasswordStrength(password))
                throw new ArgumentException("Password does not meet strength requirements.");

            string passwordHash = HashPassword(password);

            return await userRepository.CreateUserAsync(username, email, passwordHash);
        }

        private class UserRepository
        {
        }
    }
}
