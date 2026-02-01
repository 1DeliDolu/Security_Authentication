using System.ComponentModel.DataAnnotations;

namespace SafeVault.Models;

public class UserRoleAssignment
{
    public int Id { get; set; }

    [Required]
    public int UserId { get; set; }

    [Required]
    [StringLength(50)]
    public string Role { get; set; } = UserRole.User.ToString();

    public DateTime AssignedAt { get; set; } = DateTime.UtcNow;

    public User? User { get; set; }
}
