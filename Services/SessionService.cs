using System.Collections.Concurrent;
using System.Security.Cryptography;

namespace SafeVault.Services;

public class SessionService
{
    private readonly ConcurrentDictionary<string, int> _sessions = new(StringComparer.Ordinal);

    public string CreateSession(int userId)
    {
        var token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        _sessions[token] = userId;
        return token;
    }

    public bool TryGetUserId(string token, out int userId)
    {
        return _sessions.TryGetValue(token, out userId);
    }

    public void RemoveSession(string token)
    {
        _sessions.TryRemove(token, out _);
    }
}
