using System.ComponentModel.DataAnnotations;

namespace SafeVault.Models;

public class RegistrationRequest
{
    public int Id { get; set; }

    [Required]
    [StringLength(50)]
    public string Username { get; set; } = string.Empty;

    [Required]
    [StringLength(100)]
    public string Email { get; set; } = string.Empty;

    [Required]
    [StringLength(255)]
    public string PasswordHash { get; set; } = string.Empty;

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public DateTime ExpiresAt { get; set; } = DateTime.UtcNow.AddDays(1);

    public bool IsVerified { get; set; }

    [Required]
    [StringLength(255)]
    public string VerificationToken { get; set; } = string.Empty;
}
