using SafeVault.Models;

namespace SafeVault.Services;

public static class AuthorizationService
{
    private static readonly HashSet<string> AdminResources = new(StringComparer.OrdinalIgnoreCase)
    {
        "admin-dashboard",
        "admin",
        "audit-logs",
        "system-settings",
    };

    private static readonly HashSet<string> SharedResources = new(StringComparer.OrdinalIgnoreCase)
    {
        "user-data",
        "user-profile",
    };

    private static readonly HashSet<string> AdminActions = new(StringComparer.OrdinalIgnoreCase)
    {
        "manage-users",
        "view-audit-logs",
        "manage-roles",
        "view-system-settings",
    };

    private static readonly HashSet<string> UserActions = new(StringComparer.OrdinalIgnoreCase)
    {
        "view-own-profile",
        "edit-own-profile",
        "delete-own-account",
    };

    public static bool IsAdmin(User? user)
    {
        return user?.Role == UserRole.Admin;
    }

    public static bool CanAccessResource(User? user, string resource)
    {
        if (user is null || string.IsNullOrWhiteSpace(resource))
        {
            return false;
        }

        if (AdminResources.Contains(resource))
        {
            return IsAdmin(user);
        }

        if (SharedResources.Contains(resource))
        {
            return true;
        }

        return false;
    }

    public static bool AuthorizeAction(User? user, string action)
    {
        if (user is null || string.IsNullOrWhiteSpace(action))
        {
            return false;
        }

        if (AdminActions.Contains(action))
        {
            return IsAdmin(user);
        }

        if (UserActions.Contains(action))
        {
            return true;
        }

        return false;
    }
}
