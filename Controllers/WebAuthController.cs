using Microsoft.AspNetCore.Mvc;
using SafeVault.Models;
using SafeVault.Repositories;
using SafeVault.Services;

namespace SafeVault.Controllers;

[Route("auth")]
public class WebAuthController : Controller
{
    private readonly AuthenticationService _auth;
    private readonly UserRepository _repo;
    private readonly SessionService _sessions;

    public WebAuthController(
        AuthenticationService auth,
        UserRepository repo,
        SessionService sessions
    )
    {
        _auth = auth;
        _repo = repo;
        _sessions = sessions;
    }

    [HttpGet("login")]
    public IActionResult Login()
    {
        return View("~/Views/Auth/Login.cshtml", new LoginRequest());
    }

    [HttpPost("login")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Login([FromForm] LoginRequest request)
    {
        if (!ModelState.IsValid)
        {
            return View("~/Views/Auth/Login.cshtml", request);
        }

        var ip = HttpContext.Connection.RemoteIpAddress?.ToString();
        var user = await _auth.AuthenticateAsync(request.Username, request.Password, ip);
        if (user is null)
        {
            ModelState.AddModelError(string.Empty, "Invalid username or password.");
            return View("~/Views/Auth/Login.cshtml", request);
        }

        var token = _sessions.CreateSession(user.UserId);
        var cookieOptions = new CookieOptions
        {
            HttpOnly = true,
            SameSite = SameSiteMode.Strict,
            Secure = Request.IsHttps,
            Expires = DateTimeOffset.UtcNow.AddHours(8),
        };

        Response.Cookies.Append(SessionHelper.SessionCookieName, token, cookieOptions);

        return RedirectToAction(nameof(Me));
    }

    [HttpGet("register")]
    public IActionResult Register()
    {
        return View("~/Views/Auth/Register.cshtml", new RegisterRequest());
    }

    [HttpPost("register")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Register([FromForm] RegisterRequest request)
    {
        if (!ModelState.IsValid)
        {
            return View("~/Views/Auth/Register.cshtml", request);
        }

        try
        {
            await _auth.RegisterAsync(
                request.Username,
                request.Email,
                request.Password,
                UserRole.User
            );
            TempData["Toast"] = "Registration successful. Please log in.";
            TempData["ToastType"] = "success";
            return RedirectToAction(nameof(Login));
        }
        catch (ArgumentException ex)
        {
            ModelState.AddModelError(string.Empty, ex.Message);
        }
        catch (InvalidOperationException ex)
        {
            ModelState.AddModelError(string.Empty, ex.Message);
        }

        return View("~/Views/Auth/Register.cshtml", request);
    }

    [HttpGet("me")]
    public async Task<IActionResult> Me()
    {
        var user = await SessionHelper.GetUserAsync(Request, _sessions, _repo);
        if (user is null)
        {
            return RedirectToAction(nameof(Login));
        }

        return View("~/Views/Auth/Profile.cshtml", BuildProfile(user));
    }

    [HttpPost("me/password")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ChangePassword([FromForm] ChangePasswordRequest request)
    {
        var user = await SessionHelper.GetUserAsync(Request, _sessions, _repo);
        if (user is null)
        {
            return RedirectToAction(nameof(Login));
        }

        if (!ModelState.IsValid)
        {
            return View("~/Views/Auth/Profile.cshtml", BuildProfile(user));
        }

        try
        {
            await _auth.ChangePasswordAsync(user.UserId, request.CurrentPassword, request.NewPassword);
        }
        catch (ArgumentException ex)
        {
            ModelState.AddModelError(string.Empty, ex.Message);
            return View("~/Views/Auth/Profile.cshtml", BuildProfile(user));
        }
        catch (InvalidOperationException ex)
        {
            ModelState.AddModelError(string.Empty, ex.Message);
            return View("~/Views/Auth/Profile.cshtml", BuildProfile(user));
        }

        TempData["Toast"] = "Password updated successfully.";
        TempData["ToastType"] = "success";
        return RedirectToAction(nameof(Me));
    }

    [HttpPost("logout")]
    [ValidateAntiForgeryToken]
    public IActionResult Logout()
    {
        if (SessionHelper.TryGetToken(Request, out var token))
        {
            _sessions.RemoveSession(token);
        }

        Response.Cookies.Delete(SessionHelper.SessionCookieName);
        TempData["Toast"] = "Logged out successfully.";
        TempData["ToastType"] = "success";
        return RedirectToAction(nameof(Login));
    }

    private static UserProfileResponse BuildProfile(User user)
    {
        return new UserProfileResponse
        {
            Username = user.Username,
            Email = user.Email,
            Role = user.Role.ToString(),
            LastLoginAt = user.LastLoginAt,
        };
    }
}
