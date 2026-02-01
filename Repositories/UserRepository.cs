using Microsoft.EntityFrameworkCore;
using SafeVault.Data;
using SafeVault.Models;
using SafeVault.Services;

namespace SafeVault.Repositories;

public class UserRepository
{
    private readonly SafeVaultDbContext _context;

    public UserRepository(SafeVaultDbContext context)
    {
        _context = context;
    }

    public async Task<User?> GetByUsernameAsync(string username)
    {
        var normalized = InputValidationService.Normalize(username);
        return await _context.Users.FirstOrDefaultAsync(u => u.Username == normalized);
    }

    public async Task<User?> GetByIdAsync(int userId)
    {
        return await _context.Users.FirstOrDefaultAsync(u => u.UserId == userId);
    }

    public async Task<User?> GetByEmailAsync(string email)
    {
        var normalized = InputValidationService.Normalize(email);
        return await _context.Users.FirstOrDefaultAsync(u => u.Email == normalized);
    }

    public async Task<List<User>> GetAllAsync()
    {
        return await _context.Users
            .AsNoTracking()
            .OrderByDescending(u => u.CreatedAt)
            .ToListAsync();
    }

    public async Task<User> CreateUserAsync(User user)
    {
        if (user is null)
        {
            throw new ArgumentNullException(nameof(user));
        }

        var normalizedUsername = InputValidationService.Normalize(user.Username);
        var normalizedEmail = InputValidationService.Normalize(user.Email);

        if (!InputValidationService.ValidateUsername(normalizedUsername))
        {
            throw new ArgumentException("Invalid username.", nameof(user));
        }

        if (!InputValidationService.ValidateEmail(normalizedEmail))
        {
            throw new ArgumentException("Invalid email.", nameof(user));
        }

        if (string.IsNullOrWhiteSpace(user.PasswordHash))
        {
            throw new ArgumentException("Password hash is required.", nameof(user));
        }

        var exists = await _context.Users.AnyAsync(u =>
            u.Username == normalizedUsername || u.Email == normalizedEmail
        );

        if (exists)
        {
            throw new InvalidOperationException("User already exists.");
        }

        user.Username = normalizedUsername;
        user.Email = normalizedEmail;
        user.UpdatedAt = DateTime.UtcNow;

        _context.Users.Add(user);
        await _context.SaveChangesAsync();

        return user;
    }

    public async Task UpdateLastLoginAsync(int userId, DateTime loginAt)
    {
        var user = await _context.Users.FirstOrDefaultAsync(u => u.UserId == userId);
        if (user is null)
        {
            return;
        }

        user.LastLoginAt = loginAt;
        user.UpdatedAt = DateTime.UtcNow;
        await _context.SaveChangesAsync();
    }

    public async Task<bool> UpdatePasswordHashAsync(int userId, string passwordHash)
    {
        if (string.IsNullOrWhiteSpace(passwordHash))
        {
            throw new ArgumentException("Password hash is required.", nameof(passwordHash));
        }

        var user = await _context.Users.FirstOrDefaultAsync(u => u.UserId == userId);
        if (user is null)
        {
            return false;
        }

        user.PasswordHash = passwordHash;
        user.UpdatedAt = DateTime.UtcNow;
        await _context.SaveChangesAsync();
        return true;
    }

    public async Task RecordLoginAttemptAsync(int? userId, bool success, string? ipAddress)
    {
        var attempt = new LoginAttempt
        {
            UserId = userId,
            Success = success,
            IpAddress = ipAddress,
            AttemptTimestamp = DateTime.UtcNow,
        };

        _context.LoginAttempts.Add(attempt);
        await _context.SaveChangesAsync();
    }

    public async Task RecordRegistrationRequestAsync(
        string username,
        string email,
        string passwordHash
    )
    {
        var now = DateTime.UtcNow;
        var request = new RegistrationRequest
        {
            Username = username,
            Email = email,
            PasswordHash = passwordHash,
            CreatedAt = now,
            ExpiresAt = now.AddDays(1),
            IsVerified = true,
            VerificationToken = Guid.NewGuid().ToString("N"),
        };

        _context.RegistrationRequests.Add(request);
        await _context.SaveChangesAsync();
    }

    public async Task RecordAuditLogAsync(int userId, string action)
    {
        var log = new AuditLog
        {
            UserId = userId,
            Action = action,
            Timestamp = DateTime.UtcNow,
        };

        _context.AuditLogs.Add(log);
        await _context.SaveChangesAsync();
    }
}
