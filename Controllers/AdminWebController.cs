using Microsoft.AspNetCore.Mvc;
using SafeVault.Models;
using SafeVault.Repositories;
using SafeVault.Services;

namespace SafeVault.Controllers;

[Route("admin")]
public class AdminWebController : Controller
{
    private readonly UserRepository _repo;
    private readonly SessionService _sessions;
    private readonly SecurityAuditService _audit;

    public AdminWebController(UserRepository repo, SessionService sessions, SecurityAuditService audit)
    {
        _repo = repo;
        _sessions = sessions;
        _audit = audit;
    }

    [HttpGet("audit")]
    public async Task<IActionResult> Audit()
    {
        var user = await SessionHelper.GetUserAsync(Request, _sessions, _repo);
        if (user is null)
        {
            return RedirectToAction("Login", "WebAuth");
        }

        if (!AuthorizationService.AuthorizeAction(user, "view-audit-logs"))
        {
            return Forbid();
        }

        var findings = await _audit.RunAsync();
        await _repo.RecordAuditLogAsync(user.UserId, "audit_report_viewed");
        return View("~/Views/Admin/Audit.cshtml", findings);
    }

    [HttpGet("dashboard")]
    public async Task<IActionResult> Dashboard()
    {
        var user = await SessionHelper.GetUserAsync(Request, _sessions, _repo);
        if (user is null)
        {
            return RedirectToAction("Login", "WebAuth");
        }

        if (!AuthorizationService.CanAccessResource(user, "admin-dashboard"))
        {
            return Forbid();
        }

        var users = await _repo.GetAllAsync();
        var now = DateTime.UtcNow;

        var viewModel = new AdminDashboardViewModel
        {
            AdminName = user.Username,
            TotalUsers = users.Count,
            AdminUsers = users.Count(u => u.Role == UserRole.Admin),
            ActiveLast24Hours = users.Count(u =>
                u.LastLoginAt.HasValue && u.LastLoginAt.Value >= now.AddHours(-24)
            ),
            NewLast7Days = users.Count(u => u.CreatedAt >= now.AddDays(-7)),
            Users = users
                .Select(u => new AdminDashboardUser
                {
                    UserId = u.UserId,
                    Username = u.Username,
                    Email = u.Email,
                    Role = u.Role.ToString(),
                    CreatedAt = u.CreatedAt,
                    LastLoginAt = u.LastLoginAt
                })
                .ToList()
        };

        await _repo.RecordAuditLogAsync(user.UserId, "admin_dashboard_viewed");
        return View("~/Views/Admin/Dashboard.cshtml", viewModel);
    }
}
