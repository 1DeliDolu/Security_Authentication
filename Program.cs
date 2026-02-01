using Microsoft.EntityFrameworkCore;
using Pomelo.EntityFrameworkCore.MySql.Infrastructure;
using SafeVault.Data;
using SafeVault.Models;
using SafeVault.Repositories;
using SafeVault.Services;

var builder = WebApplication.CreateBuilder(args);

var connectionString =
    builder.Configuration.GetConnectionString("SecurityAuthentication")
    ?? "Server=127.0.0.1;Port=3306;Database=security_authentication;User=root;Password=;";

builder.Services.AddDbContext<SafeVaultDbContext>(options =>
    options.UseMySql(connectionString, ServerVersion.AutoDetect(connectionString))
);

builder.Services.AddScoped<UserRepository>();
builder.Services.AddScoped<AuthenticationService>();
builder.Services.AddSingleton<SessionService>();
builder.Services.AddSingleton<SecurityAuditService>();

builder.Services.AddControllersWithViews();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseHsts();
}

app.UseHttpsRedirection();
app.Use(
    async (context, next) =>
    {
        var isSwagger = context.Request.Path.StartsWithSegments("/swagger");

        context.Response.Headers["X-Content-Type-Options"] = "nosniff";
        context.Response.Headers["X-Frame-Options"] = "DENY";
        context.Response.Headers["Referrer-Policy"] = "no-referrer";
        context.Response.Headers["Content-Security-Policy"] = isSwagger
            ? "default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
                + "font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; script-src 'self' 'unsafe-inline';"
            : "default-src 'self'; style-src 'self' https://fonts.googleapis.com; "
                + "font-src 'self' https://fonts.gstatic.com; img-src 'self'; script-src 'self';";

        await next();
    }
);

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseStaticFiles();

app.MapGet("/", () => Results.Redirect("/auth/login"));

using (var scope = app.Services.CreateScope())
{
    var repo = scope.ServiceProvider.GetRequiredService<UserRepository>();
    var auth = scope.ServiceProvider.GetRequiredService<AuthenticationService>();

    if (await repo.GetByUsernameAsync("admin") is null)
    {
        await auth.RegisterAsync(
            username: "admin",
            email: "admin@safevault.com",
            password: "AdminPass123!",
            role: UserRole.Admin
        );
    }
}

app.MapControllers();
app.MapControllerRoute(name: "default", pattern: "{controller=WebAuth}/{action=Login}/{id?}");

app.Run();
