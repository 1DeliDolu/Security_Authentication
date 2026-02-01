using Microsoft.EntityFrameworkCore;
using SafeVault.Models;

namespace SafeVault.Data;

public class SafeVaultDbContext : DbContext
{
    public SafeVaultDbContext(DbContextOptions<SafeVaultDbContext> options)
        : base(options) { }

    public DbSet<User> Users => Set<User>();
    public DbSet<UserProfile> UserProfiles => Set<UserProfile>();
    public DbSet<PasswordSalt> PasswordSalts => Set<PasswordSalt>();
    public DbSet<LoginAttempt> LoginAttempts => Set<LoginAttempt>();
    public DbSet<RegistrationRequest> RegistrationRequests => Set<RegistrationRequest>();
    public DbSet<AuditLog> AuditLogs => Set<AuditLog>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<User>(entity =>
        {
            entity.ToTable("users");
            entity.HasKey(u => u.UserId);
            entity.Property(u => u.UserId).HasColumnName("id");
            entity.Property(u => u.Username).HasColumnName("username").HasMaxLength(50);
            entity.Property(u => u.Email).HasColumnName("email").HasMaxLength(100);
            entity.Property(u => u.PasswordHash).HasColumnName("password_hash").HasMaxLength(255);
            entity.Property(u => u.Role)
                .HasColumnName("role")
                .HasConversion<string>()
                .HasMaxLength(20);
            entity.Property(u => u.CreatedAt).HasColumnName("created_at");
            entity.Property(u => u.UpdatedAt).HasColumnName("updated_at");
            entity.Property(u => u.LastLoginAt).HasColumnName("last_login_at");
            entity.HasIndex(u => u.Username).IsUnique();
            entity.HasIndex(u => u.Email).IsUnique();
        });

        modelBuilder.Entity<PasswordSalt>(entity =>
        {
            entity.ToTable("password_salts");
            entity.HasKey(s => s.Id);
            entity.Property(s => s.Id).HasColumnName("id");
            entity.Property(s => s.UserId).HasColumnName("user_id");
            entity.Property(s => s.Salt).HasColumnName("password_salt").HasMaxLength(255);
            entity.Property(s => s.CreatedAt).HasColumnName("created_at");
            entity.HasOne(s => s.User)
                .WithMany()
                .HasForeignKey(s => s.UserId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<LoginAttempt>(entity =>
        {
            entity.ToTable("login_attempts");
            entity.HasKey(a => a.Id);
            entity.Property(a => a.Id).HasColumnName("id");
            entity.Property(a => a.UserId).HasColumnName("user_id");
            entity.Property(a => a.Success).HasColumnName("success");
            entity.Property(a => a.IpAddress).HasColumnName("ip_address").HasMaxLength(45);
            entity.Property(a => a.AttemptTimestamp).HasColumnName("attempt_timestamp");
            entity.HasOne(a => a.User)
                .WithMany()
                .HasForeignKey(a => a.UserId)
                .OnDelete(DeleteBehavior.SetNull);
        });

        modelBuilder.Entity<UserProfile>(entity =>
        {
            entity.ToTable("user_profiles");
            entity.HasKey(p => p.Id);
            entity.Property(p => p.Id).HasColumnName("id");
            entity.Property(p => p.UserId).HasColumnName("user_id");
            entity.Property(p => p.FullName).HasColumnName("full_name").HasMaxLength(100);
            entity.Property(p => p.Bio).HasColumnName("bio");
            entity.Property(p => p.ProfilePictureUrl).HasColumnName("profile_picture_url").HasMaxLength(255);
            entity.Property(p => p.PhoneNumber).HasColumnName("phone_number").HasMaxLength(20);
            entity.Property(p => p.CreatedAt).HasColumnName("created_at");
            entity.Property(p => p.UpdatedAt).HasColumnName("updated_at");
            entity.HasOne(p => p.User)
                .WithMany()
                .HasForeignKey(p => p.UserId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<RegistrationRequest>(entity =>
        {
            entity.ToTable("registration_requests");
            entity.HasKey(r => r.Id);
            entity.Property(r => r.Id).HasColumnName("id");
            entity.Property(r => r.Username).HasColumnName("username").HasMaxLength(50);
            entity.Property(r => r.Email).HasColumnName("email").HasMaxLength(100);
            entity.Property(r => r.PasswordHash).HasColumnName("password_hash").HasMaxLength(255);
            entity.Property(r => r.CreatedAt).HasColumnName("created_at");
            entity.Property(r => r.ExpiresAt).HasColumnName("expires_at");
            entity.Property(r => r.IsVerified).HasColumnName("is_verified");
            entity.Property(r => r.VerificationToken).HasColumnName("verification_token").HasMaxLength(255);
        });

        modelBuilder.Entity<AuditLog>(entity =>
        {
            entity.ToTable("audit_logs");
            entity.HasKey(l => l.Id);
            entity.Property(l => l.Id).HasColumnName("id");
            entity.Property(l => l.UserId).HasColumnName("user_id");
            entity.Property(l => l.Action).HasColumnName("action").HasMaxLength(100);
            entity.Property(l => l.Timestamp).HasColumnName("timestamp");
            entity.HasOne(l => l.User)
                .WithMany()
                .HasForeignKey(l => l.UserId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        base.OnModelCreating(modelBuilder);
    }
}
