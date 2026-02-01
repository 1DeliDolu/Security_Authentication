using SafeVault.Models;

namespace SafeVault.Services
{
    /// <summary>
    /// Authorization service providing role-based access control (RBAC).
    /// Determines whether a user has permission to perform specific actions.
    /// </summary>
    public class AuthorizationService
    {
        /// <summary>
        /// Checks if a user has a specific role.
        /// </summary>
        public static bool HasRole(User? user, UserRole requiredRole)
        {
            if (user == null)
                return false;

            return user.Role == requiredRole || user.Role == UserRole.Admin;
        }

        /// <summary>
        /// Checks if a user is an admin.
        /// </summary>
        public static bool IsAdmin(User? user)
        {
            return user?.Role == UserRole.Admin;
        }

        /// <summary>
        /// Checks if a user is a regular user.
        /// </summary>
        public static bool IsRegularUser(User? user)
        {
            return user?.Role == UserRole.User;
        }

        /// <summary>
        /// Checks if a user has permission to access a protected resource.
        /// </summary>
        public static bool CanAccessResource(User? user, string resourceName)
        {
            if (user == null)
                return false;

            // Define resource access rules
            return resourceName switch
            {
                "admin-dashboard" => IsAdmin(user),
                "user-profile" => user != null,
                "settings" => IsAdmin(user),
                "user-data" => user != null,
                _ => false
            };
        }

        /// <summary>
        /// Authorizes a user to perform an action.
        /// Returns true if authorized, false otherwise.
        /// </summary>
        public static bool AuthorizeAction(User? user, string action)
        {
            if (user == null)
                return false;

            return action switch
            {
                "view-own-profile" => user != null,
                "edit-own-profile" => user != null,
                "delete-own-account" => user != null,
                "manage-users" => IsAdmin(user),
                "view-audit-logs" => IsAdmin(user),
                "manage-roles" => IsAdmin(user),
                "view-system-settings" => IsAdmin(user),
                "edit-system-settings" => IsAdmin(user),
                _ => false
            };
        }
    }
}
