using System.ComponentModel.DataAnnotations;

namespace SafeVault.Models;

public class AuditLog
{
    public int Id { get; set; }

    public int UserId { get; set; }

    [Required]
    [StringLength(100)]
    public string Action { get; set; } = string.Empty;

    public DateTime Timestamp { get; set; } = DateTime.UtcNow;

    public User? User { get; set; }
}
