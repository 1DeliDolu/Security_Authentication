using SafeVault.Models;
using SafeVault.Repositories;
using SafeVault.Services;

namespace SafeVault.Controllers;

internal static class SessionHelper
{
    internal const string SessionCookieName = "SafeVault-Session";

    internal static bool TryGetToken(HttpRequest request, out string token)
    {
        token = string.Empty;

        if (request.Headers.TryGetValue("Authorization", out var authHeader))
        {
            var headerValue = authHeader.ToString();
            if (headerValue.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            {
                token = headerValue["Bearer ".Length..].Trim();
            }
        }

        if (
            string.IsNullOrWhiteSpace(token)
            && request.Headers.TryGetValue("X-Session-Token", out var tokenHeader)
        )
        {
            token = tokenHeader.ToString().Trim();
        }

        if (
            string.IsNullOrWhiteSpace(token)
            && request.Cookies.TryGetValue(SessionCookieName, out var cookieToken)
        )
        {
            token = cookieToken.Trim();
        }

        return !string.IsNullOrWhiteSpace(token);
    }

    internal static async Task<User?> GetUserAsync(
        HttpRequest request,
        SessionService sessions,
        UserRepository repo
    )
    {
        if (!TryGetToken(request, out var token))
        {
            return null;
        }

        if (!sessions.TryGetUserId(token, out var userId))
        {
            return null;
        }

        return await repo.GetByIdAsync(userId);
    }
}
