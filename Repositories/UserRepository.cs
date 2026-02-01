using SafeVault.Data;
using SafeVault.Models;
using SafeVault.Services;

namespace SafeVault.Repositories
{
    /// <summary>
    /// User repository with secure parameterized queries to prevent SQL injection.
    /// </summary>
    public class UserRepository
    {
        private readonly SafeVaultDbContext _context;

        public UserRepository(SafeVaultDbContext context)
        {
            _context = context;
        }

        /// <summary>
        /// Creates a new user with validated and sanitized data.
        /// Uses parameterized queries (EF Core) to prevent SQL injection.
        /// </summary>
        public async Task<bool> CreateUserAsync(string username, string email, string passwordHash)
        {
            // Validate inputs
            if (!InputValidationService.ValidateUsername(username))
                throw new ArgumentException("Invalid username format.");

            if (!InputValidationService.ValidateEmail(email))
                throw new ArgumentException("Invalid email format.");

            if (string.IsNullOrWhiteSpace(passwordHash))
                throw new ArgumentException("Password hash cannot be empty.");

            // Check if user already exists (parameterized query via EF)
            var existingUser = await _context.Users
                .FirstOrDefaultAsync(u => u.Username == username || u.Email == email);

            if (existingUser != null)
                return false;

            // Create and add user
            var user = new User
            {
                Username = username,
                Email = email,
                PasswordHash = passwordHash
            };

            _context.Users.Add(user);
            await _context.SaveChangesAsync();
            return true;
        }

        /// <summary>
        /// Retrieves a user by username using parameterized query.
        /// </summary>
        public async Task<User?> GetUserByUsernameAsync(string username)
        {
            if (string.IsNullOrWhiteSpace(username))
                return null;

            // Parameterized query prevents SQL injection
            return await _context.Users
                .FirstOrDefaultAsync(u => u.Username == username);
        }

        /// <summary>
        /// Retrieves a user by email using parameterized query.
        /// </summary>
        public async Task<User?> GetUserByEmailAsync(string email)
        {
            if (string.IsNullOrWhiteSpace(email))
                return null;

            // Parameterized query prevents SQL injection
            return await _context.Users
                .FirstOrDefaultAsync(u => u.Email == email);
        }

        /// <summary>
        /// Retrieves a user by ID using parameterized query.
        /// </summary>
        public async Task<User?> GetUserByIdAsync(int userId)
        {
            if (userId <= 0)
                return null;

            // Parameterized query prevents SQL injection
            return await _context.Users.FindAsync(userId);
        }

        /// <summary>
        /// Updates user email with validation and sanitization.
        /// </summary>
        public async Task<bool> UpdateUserEmailAsync(int userId, string newEmail)
        {
            if (!InputValidationService.ValidateEmail(newEmail))
                throw new ArgumentException("Invalid email format.");

            var user = await GetUserByIdAsync(userId);
            if (user == null)
                return false;

            user.Email = newEmail;
            _context.Users.Update(user);
            await _context.SaveChangesAsync();
            return true;
        }

        /// <summary>
        /// Updates user with new data.
        /// </summary>
        public async Task<bool> UpdateUserAsync(User user)
        {
            if (user == null)
                throw new ArgumentNullException(nameof(user));

            _context.Users.Update(user);
            await _context.SaveChangesAsync();
            return true;
        }

        /// <summary>
        /// Retrieves all users (admin only).
        /// </summary>
        public async Task<List<User>> GetAllUsersAsync()
        {
            return await _context.Users.ToListAsync();
        }

        /// <summary>
        /// Updates user role (admin only).
        /// </summary>
        public async Task<bool> UpdateUserRoleAsync(int userId, UserRole newRole)
        {
            var user = await GetUserByIdAsync(userId);
            if (user == null)
                return false;

            user.Role = newRole;
            _context.Users.Update(user);
            await _context.SaveChangesAsync();
            return true;
        }

        /// <summary>
        /// Deletes a user by ID.
        /// </summary>
        public async Task<bool> DeleteUserAsync(int userId)
        {
            var user = await GetUserByIdAsync(userId);
            if (user == null)
                return false;

            _context.Users.Remove(user);
            await _context.SaveChangesAsync();
            return true;
        }
    }
}
