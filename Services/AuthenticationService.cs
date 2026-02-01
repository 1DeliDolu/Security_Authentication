using System.Security.Cryptography;
using SafeVault.Models;
using SafeVault.Repositories;

namespace SafeVault.Services;

public class AuthenticationService
{
    private const int Iterations = 10_000;
    private const int SaltSize = 16;
    private const int KeySize = 32;

    private readonly UserRepository _userRepository;

    public AuthenticationService(UserRepository userRepository)
    {
        _userRepository = userRepository;
    }

    public static string HashPassword(string password)
    {
        if (string.IsNullOrWhiteSpace(password))
        {
            throw new ArgumentException("Password is required.", nameof(password));
        }

        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        using var pbkdf2 = new Rfc2898DeriveBytes(
            password,
            salt,
            Iterations,
            HashAlgorithmName.SHA256
        );
        var hash = pbkdf2.GetBytes(KeySize);

        return $"{Convert.ToBase64String(salt)}.{Convert.ToBase64String(hash)}";
    }

    public static bool VerifyPassword(string password, string storedHash)
    {
        if (string.IsNullOrWhiteSpace(password) || string.IsNullOrWhiteSpace(storedHash))
        {
            return false;
        }

        var parts = storedHash.Split('.', 2);
        if (parts.Length != 2)
        {
            return false;
        }

        byte[] salt;
        byte[] expectedHash;

        try
        {
            salt = Convert.FromBase64String(parts[0]);
            expectedHash = Convert.FromBase64String(parts[1]);
        }
        catch (FormatException)
        {
            return false;
        }

        using var pbkdf2 = new Rfc2898DeriveBytes(
            password,
            salt,
            Iterations,
            HashAlgorithmName.SHA256
        );
        var actualHash = pbkdf2.GetBytes(expectedHash.Length);

        return CryptographicOperations.FixedTimeEquals(actualHash, expectedHash);
    }

    public async Task<bool> RegisterAsync(
        string username,
        string email,
        string password,
        UserRole role = UserRole.User
    )
    {
        var normalizedUsername = InputValidationService.Normalize(username);
        var normalizedEmail = InputValidationService.Normalize(email);

        if (!InputValidationService.ValidateUsername(normalizedUsername))
        {
            throw new ArgumentException("Invalid username.", nameof(username));
        }

        if (!InputValidationService.ValidateEmail(normalizedEmail))
        {
            throw new ArgumentException("Invalid email.", nameof(email));
        }

        if (!InputValidationService.ValidatePassword(password))
        {
            throw new ArgumentException("Invalid password.", nameof(password));
        }

        var existing = await _userRepository.GetByUsernameAsync(normalizedUsername);
        if (existing is not null)
        {
            throw new InvalidOperationException("User already exists.");
        }

        var existingEmail = await _userRepository.GetByEmailAsync(normalizedEmail);
        if (existingEmail is not null)
        {
            throw new InvalidOperationException("User already exists.");
        }

        var hash = HashPassword(password);
        var user = new User
        {
            Username = normalizedUsername,
            Email = normalizedEmail,
            PasswordHash = hash,
            Role = role,
        };

        await _userRepository.RecordRegistrationRequestAsync(
            normalizedUsername,
            normalizedEmail,
            hash
        );
        await _userRepository.CreateUserAsync(user);
        return true;
    }

    public async Task ChangePasswordAsync(int userId, string currentPassword, string newPassword)
    {
        if (userId <= 0)
        {
            throw new ArgumentException("Invalid user.", nameof(userId));
        }

        if (string.IsNullOrWhiteSpace(currentPassword))
        {
            throw new ArgumentException("Current password is required.", nameof(currentPassword));
        }

        if (!InputValidationService.ValidatePassword(newPassword))
        {
            throw new ArgumentException("Invalid password.", nameof(newPassword));
        }

        if (currentPassword == newPassword)
        {
            throw new ArgumentException(
                "New password must be different from the current password.",
                nameof(newPassword)
            );
        }

        var user = await _userRepository.GetByIdAsync(userId);
        if (user is null)
        {
            throw new InvalidOperationException("User not found.");
        }

        if (!VerifyPassword(currentPassword, user.PasswordHash))
        {
            throw new InvalidOperationException("Current password is incorrect.");
        }

        var hash = HashPassword(newPassword);
        var updated = await _userRepository.UpdatePasswordHashAsync(user.UserId, hash);
        if (!updated)
        {
            throw new InvalidOperationException("Unable to update password.");
        }
    }

    public async Task<User?> AuthenticateAsync(
        string username,
        string password,
        string? ipAddress = null
    )
    {
        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
        {
            return null;
        }

        var normalizedUsername = InputValidationService.Normalize(username);
        var user = await _userRepository.GetByUsernameAsync(normalizedUsername);

        if (user is null)
        {
            await _userRepository.RecordLoginAttemptAsync(null, false, ipAddress);
            return null;
        }

        if (!VerifyPassword(password, user.PasswordHash))
        {
            await _userRepository.RecordLoginAttemptAsync(user.UserId, false, ipAddress);
            return null;
        }

        var loginAt = DateTime.UtcNow;
        await _userRepository.RecordLoginAttemptAsync(user.UserId, true, ipAddress);
        await _userRepository.UpdateLastLoginAsync(user.UserId, loginAt);
        user.LastLoginAt = loginAt;

        return user;
    }
}
