using Xunit;
using SafeVault.Services;

namespace SafeVault.Tests
{
    /// <summary>
    /// Security audit tests to validate that all identified vulnerabilities have been addressed.
    /// </summary>
    public class SecurityAuditTests
    {
        [Fact]
        public void AuditReport_GeneratesVulnerabilities()
        {
            // Act
            var report = SecurityAuditService.GenerateAuditReport();

            // Assert
            Assert.NotEmpty(report);
            Assert.True(report.Count >= 8); // At least 8 vulnerabilities identified
        }

        [Fact]
        public void AuditReport_AllVulnerabilitiesAddressed()
        {
            // Act
            var report = SecurityAuditService.GenerateAuditReport();

            // Assert
            // All vulnerabilities should be either Fixed or Hardened
            var notAddressed = report.Where(v => v.Status != "Fixed" && v.Status != "Hardened").ToList();
            Assert.Empty(notAddressed);
        }

        [Fact]
        public void AuditReport_CriticalVulnerabilitiesMitigated()
        {
            // Act
            var report = SecurityAuditService.GenerateAuditReport();

            // Assert
            var criticalVulnerabilities = report.Where(v => v.Severity == "Critical").ToList();
            Assert.NotEmpty(criticalVulnerabilities);

            // All critical vulnerabilities should be fixed or hardened
            foreach (var vuln in criticalVulnerabilities)
            {
                Assert.True(
                    vuln.Status == "Fixed" || vuln.Status == "Hardened",
                    $"Critical vulnerability '{vuln.VulnerabilityName}' not properly mitigated"
                );
            }
        }

        [Theory]
        [InlineData("SQL Injection")]
        [InlineData("Cross-Site Scripting (XSS)")]
        [InlineData("Weak Password Hashing")]
        [InlineData("Insufficient Input Validation")]
        [InlineData("Unauthorized Access to Admin Resources")]
        public void AuditReport_SpecificVulnerabilityExists(string vulnerabilityName)
        {
            // Act
            var report = SecurityAuditService.GenerateAuditReport();

            // Assert
            var vuln = report.FirstOrDefault(v => v.VulnerabilityName == vulnerabilityName);
            Assert.NotNull(vuln);
            Assert.NotEmpty(vuln.Mitigation);
        }

        [Fact]
        public void AuditReport_SQLInjectionFixed()
        {
            // Act
            var report = SecurityAuditService.GenerateAuditReport();
            var sqlInjectionVuln = report.First(v => v.VulnerabilityName == "SQL Injection");

            // Assert
            Assert.Equal("Critical", sqlInjectionVuln.Severity);
            Assert.Equal("Fixed", sqlInjectionVuln.Status);
            Assert.Contains("parameterized", sqlInjectionVuln.Mitigation.ToLower());
            Assert.Contains("UserRepository", sqlInjectionVuln.AffectedComponent);
        }

        [Fact]
        public void AuditReport_XSSFixed()
        {
            // Act
            var report = SecurityAuditService.GenerateAuditReport();
            var xssVuln = report.First(v => v.VulnerabilityName == "Cross-Site Scripting (XSS)");

            // Assert
            Assert.Equal("Critical", xssVuln.Severity);
            Assert.Equal("Fixed", xssVuln.Status);
            Assert.Contains("HTML", xssVuln.Mitigation.ToUpper());
            Assert.Contains("InputValidationService", xssVuln.AffectedComponent);
        }

        [Fact]
        public void AuditReport_AuthorizationFixed()
        {
            // Act
            var report = SecurityAuditService.GenerateAuditReport();
            var authVuln = report.First(v => v.VulnerabilityName == "Unauthorized Access to Admin Resources");

            // Assert
            Assert.Equal("Critical", authVuln.Severity);
            Assert.Equal("Fixed", authVuln.Status);
            Assert.Contains("RBAC", authVuln.Mitigation);
        }

        [Fact]
        public void AuditReport_PasswordHashingHardened()
        {
            // Act
            var report = SecurityAuditService.GenerateAuditReport();
            var hashVuln = report.First(v => v.VulnerabilityName == "Weak Password Hashing");

            // Assert
            Assert.Equal("High", hashVuln.Severity);
            Assert.Equal("Hardened", hashVuln.Status);
            Assert.Contains("PBKDF2", hashVuln.Mitigation);
            Assert.Contains("10,000", hashVuln.Mitigation);
        }

        [Fact]
        public void AuditReport_ContainsMitigationStrategies()
        {
            // Act
            var report = SecurityAuditService.GenerateAuditReport();

            // Assert
            foreach (var vuln in report)
            {
                Assert.NotEmpty(vuln.Mitigation);
                Assert.NotEmpty(vuln.Risk);
                Assert.NotEmpty(vuln.Description);
            }
        }
    }
}
