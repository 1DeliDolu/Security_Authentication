using Microsoft.AspNetCore.Mvc;
using SafeVault.Models;
using SafeVault.Repositories;
using SafeVault.Services;

namespace SafeVault.Controllers;

[ApiController]
[Route("api/auth")]
public class AuthController : ControllerBase
{
    private readonly AuthenticationService _auth;
    private readonly UserRepository _repo;
    private readonly SessionService _sessions;

    public AuthController(AuthenticationService auth, UserRepository repo, SessionService sessions)
    {
        _auth = auth;
        _repo = repo;
        _sessions = sessions;
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterRequest request)
    {
        if (!ModelState.IsValid)
        {
            return ValidationProblem(ModelState);
        }

        try
        {
            await _auth.RegisterAsync(
                request.Username,
                request.Email,
                request.Password,
                UserRole.User
            );
            return Ok(new { message = "User registered." });
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

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
        if (!ModelState.IsValid)
        {
            return ValidationProblem(ModelState);
        }

        var ip = HttpContext.Connection.RemoteIpAddress?.ToString();
        var user = await _auth.AuthenticateAsync(request.Username, request.Password, ip);
        if (user is null)
        {
            return Unauthorized(new { error = "Invalid credentials." });
        }

        var token = _sessions.CreateSession(user.UserId);
        var response = new AuthResponse
        {
            Token = token,
            Username = user.Username,
            Role = user.Role.ToString(),
            LastLoginAt = user.LastLoginAt,
        };

        return Ok(response);
    }

    [HttpPost("logout")]
    public IActionResult Logout()
    {
        if (!SessionHelper.TryGetToken(Request, out var token))
        {
            return Unauthorized(new { error = "Missing session token." });
        }

        _sessions.RemoveSession(token);
        return Ok(new { message = "Logged out." });
    }

    [HttpGet("me")]
    public async Task<IActionResult> Me()
    {
        var user = await SessionHelper.GetUserAsync(Request, _sessions, _repo);
        if (user is null)
        {
            return Unauthorized(new { error = "Invalid session." });
        }

        var profile = new UserProfileResponse
        {
            Username = user.Username,
            Email = user.Email,
            Role = user.Role.ToString(),
            LastLoginAt = user.LastLoginAt,
        };

        return Ok(profile);
    }
}
