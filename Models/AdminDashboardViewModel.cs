namespace SafeVault.Models;

public class AdminDashboardViewModel
{
    public string AdminName { get; set; } = string.Empty;
    public int TotalUsers { get; set; }
    public int AdminUsers { get; set; }
    public int ActiveLast24Hours { get; set; }
    public int NewLast7Days { get; set; }
    public IReadOnlyList<AdminDashboardUser> Users { get; set; } = Array.Empty<AdminDashboardUser>();
}

public class AdminDashboardUser
{
    public int UserId { get; set; }
    public string Username { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public string Role { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; }
    public DateTime? LastLoginAt { get; set; }
}
