using System.ComponentModel.DataAnnotations;

namespace SafeVault.Models;

public class LoginAttempt
{
    public int Id { get; set; }

    public int? UserId { get; set; }

    public bool Success { get; set; }

    [StringLength(64)]
    public string? IpAddress { get; set; }

    public DateTime AttemptTimestamp { get; set; } = DateTime.UtcNow;

    public User? User { get; set; }
}
