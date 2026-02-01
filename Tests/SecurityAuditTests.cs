using NUnit.Framework;
using SafeVault.Services;

namespace SafeVault.Tests;

[TestFixture]
public class SecurityAuditTests
{
    [Test]
    public async Task RunAsync_ReturnsExpectedFindings()
    {
        var audit = new SecurityAuditService();

        var findings = await audit.RunAsync();

        Assert.That(findings, Has.Exactly(1).Matches<SecurityAuditFinding>(f => f.Id == SecurityAuditFindingIds.SqlInjection));
        Assert.That(findings, Has.Exactly(1).Matches<SecurityAuditFinding>(f => f.Id == SecurityAuditFindingIds.Xss));
        Assert.That(findings, Has.Exactly(1).Matches<SecurityAuditFinding>(f => f.Id == SecurityAuditFindingIds.WeakPasswordHashing));
        Assert.That(findings, Has.Exactly(1).Matches<SecurityAuditFinding>(f => f.Id == SecurityAuditFindingIds.InputValidation));
        Assert.That(findings, Has.Exactly(1).Matches<SecurityAuditFinding>(f => f.Id == SecurityAuditFindingIds.UnauthorizedAccess));
        Assert.That(findings, Has.Exactly(1).Matches<SecurityAuditFinding>(f => f.Id == SecurityAuditFindingIds.PlaintextTransmission));
        Assert.That(findings, Has.Exactly(1).Matches<SecurityAuditFinding>(f => f.Id == SecurityAuditFindingIds.SqlConcatenation));
        Assert.That(findings, Has.Exactly(1).Matches<SecurityAuditFinding>(f => f.Id == SecurityAuditFindingIds.UnescapedOutput));
    }

    [Test]
    public async Task RunAsync_DoesNotReportUnresolvedCriticalFindings()
    {
        var audit = new SecurityAuditService();

        var findings = await audit.RunAsync();

        Assert.That(findings.Any(f => f.Severity == SecuritySeverity.Critical && !f.IsResolved), Is.False);
    }
}
