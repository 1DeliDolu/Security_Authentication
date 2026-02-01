using System.ComponentModel.DataAnnotations;

namespace SafeVault.Models;

public class UserProfile
{
    public int Id { get; set; }

    [Required]
    public int UserId { get; set; }

    [StringLength(100)]
    public string? FullName { get; set; }

    public string? Bio { get; set; }

    [StringLength(255)]
    public string? ProfilePictureUrl { get; set; }

    [StringLength(20)]
    public string? PhoneNumber { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;

    public User? User { get; set; }
}
