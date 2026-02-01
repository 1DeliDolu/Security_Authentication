using Microsoft.AspNetCore.Mvc;
using SafeVault.Models;
using SafeVault.Repositories;
using SafeVault.Services;

namespace SafeVault.Controllers;

[ApiController]
[Route("api/admin")]
public class AdminController : ControllerBase
{
    private readonly AuthenticationService _auth;
    private readonly UserRepository _repo;
    private readonly SessionService _sessions;
    private readonly SecurityAuditService _audit;

    public AdminController(
        AuthenticationService auth,
        UserRepository repo,
        SessionService sessions,
        SecurityAuditService audit)
    {
        _auth = auth;
        _repo = repo;
        _sessions = sessions;
        _audit = audit;
    }

    [HttpGet("dashboard")]
    public async Task<IActionResult> Dashboard()
    {
        var user = await SessionHelper.GetUserAsync(Request, _sessions, _repo);
        if (user is null)
        {
            return Unauthorized(new { error = "Invalid session." });
        }

        if (!AuthorizationService.CanAccessResource(user, "admin-dashboard"))
        {
            return Forbid();
        }

        return Ok(
            new
            {
                message = "Welcome to the admin dashboard.",
                user = user.Username,
                role = user.Role.ToString(),
            }
        );
    }

    [HttpPost("users")]
    public async Task<IActionResult> CreateUser([FromBody] AdminCreateUserRequest request)
    {
        if (!ModelState.IsValid)
        {
            return ValidationProblem(ModelState);
        }

        var user = await SessionHelper.GetUserAsync(Request, _sessions, _repo);
        if (user is null)
        {
            return Unauthorized(new { error = "Invalid session." });
        }

        if (!AuthorizationService.AuthorizeAction(user, "manage-users"))
        {
            return Forbid();
        }

        try
        {
            await _auth.RegisterAsync(
                request.Username,
                request.Email,
                request.Password,
                request.Role
            );
            await _repo.RecordAuditLogAsync(user.UserId, "admin_user_create");
            return Ok(new { message = "User created.", role = request.Role.ToString() });
        }
        catch (ArgumentException ex)
        {
            return BadRequest(new { error = ex.Message });
        }
        catch (InvalidOperationException ex)
        {
            return Conflict(new { error = ex.Message });
        }
    }

    [HttpGet("audit")]
    public async Task<IActionResult> Audit()
    {
        var user = await SessionHelper.GetUserAsync(Request, _sessions, _repo);
        if (user is null)
        {
            return Unauthorized(new { error = "Invalid session." });
        }

        if (!AuthorizationService.AuthorizeAction(user, "view-audit-logs"))
        {
            return Forbid();
        }

        var findings = await _audit.RunAsync();
        await _repo.RecordAuditLogAsync(user.UserId, "audit_report_viewed");
        return Ok(findings);
    }
}
