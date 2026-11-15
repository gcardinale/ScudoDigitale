// ╔═══════════════════════════════════════════════════════════════╗
// ║   ███████╗ ██████╗██╗   ██╗██████╗  ██████╗                   ║
// ║   ██╔════╝██╔════╝██║   ██║██╔══██╗██╔═══██╗                  ║
// ║   ███████╗██║     ██║   ██║██║  ██║██║   ██║                  ║
// ║   ╚════██║██║     ██║   ██║██║  ██║██║   ██║                  ║
// ║   ███████║╚██████╗╚██████╔╝██████╔╝╚██████╔╝  D I G I T A L E ║
// ║   ╚══════╝ ╚═════╝ ╚═════╝ ╚═════╝  ╚═════╝                   ║
// ║   Security check: network, Wi-Fi, websites, email, Bluetooth, ║
// ║   GDPR and NIS2.   © 2026 Gaetano Cardinale — gcardinale.it   ║
// ╠═══════════════════════════════════════════════════════════════╣
// ║ SPDX-License-Identifier: AGPL-3.0-or-later                    ║
// ║ Attribution required (AGPL sec. 7(b)): see NOTICE file        ║
// ╚═══════════════════════════════════════════════════════════════╝

using ScudoDigitale.Core;

namespace ScudoDigitale.Core.Tests;

public class CheckEngineTests
{
    private static readonly Target Domain = new(TargetKind.Domain, "example.com");
    private static readonly Target OtherDomain = new(TargetKind.Domain, "example.org");
    private static readonly Target Network = new(TargetKind.Network, "192.168.1.0/24");
    private static readonly Profile Individual = Profile.Individual();
    private static readonly CheckResult Nothing = new CheckResult.Executed([]);

    [Fact]
    public void Constructor_WhenScopeGuardIsNull_ShouldThrow()
    {
        Assert.Throws<ArgumentNullException>(() => new CheckEngine(null!));
    }

    [Fact]
    public async Task RunAsync_WhenArgumentsAreNull_ShouldThrow()
    {
        var engine = new CheckEngine(FakeScopeGuard.Allowing());
        var scope = Make.Scope(Domain);

        await Assert.ThrowsAsync<ArgumentNullException>(() => engine.RunAsync(null!, Individual, scope, TestContext.Current.CancellationToken));
        await Assert.ThrowsAsync<ArgumentNullException>(() => engine.RunAsync([], null!, scope, TestContext.Current.CancellationToken));
        await Assert.ThrowsAsync<ArgumentNullException>(() => engine.RunAsync([], Individual, null!, TestContext.Current.CancellationToken));
        await Assert.ThrowsAsync<ArgumentNullException>(() => engine.RunAsync([null!], Individual, scope, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task RunAsync_WhenChecksMatchSomeTargets_ShouldRunEachCheckOnlyOnTargetsOfItsKind()
    {
        var mail = FakeCheck.Returning("MAIL-SPF-001", TargetKind.Domain, Nothing);
        var lan = FakeCheck.Returning("NET-PORT-001", TargetKind.Network, Nothing);
        var wifi = FakeCheck.Returning("WIFI-ENC-001", TargetKind.LocalMachine, Nothing);
        var engine = new CheckEngine(FakeScopeGuard.Allowing());

        var runs = await engine.RunAsync([mail, lan, wifi], Individual, Make.Scope(Domain, Network, OtherDomain), TestContext.Current.CancellationToken);

        Assert.Equal(
            [("MAIL-SPF-001", Domain), ("NET-PORT-001", Network), ("MAIL-SPF-001", OtherDomain)],
            runs.Select(r => (r.CheckId, r.Target)));
        Assert.Equal(0, wifi.Calls);
        Assert.All(runs, r => Assert.Equal(CheckArea.Email, r.Area));
    }

    [Fact]
    public async Task RunAsync_WhenCheckRuns_ShouldPassTargetProfileAndScope()
    {
        CheckContext? seen = null;
        var check = new FakeCheck("MAIL-SPF-001", TargetKind.Domain, (context, _) =>
        {
            seen = context;
            return Task.FromResult(Nothing);
        });
        var scope = Make.Scope(Domain);
        var profile = Profile.Company("Casa SRL");

        await new CheckEngine(FakeScopeGuard.Allowing()).RunAsync([check], profile, scope, TestContext.Current.CancellationToken);

        Assert.Equal(new CheckContext(Domain, profile, scope), seen);
    }

    [Fact]
    public async Task RunAsync_WhenCheckReturnsAResult_ShouldReportItUnchanged()
    {
        var executed = new CheckResult.Executed([Make.Finding()]);
        var skipped = new CheckResult.Skipped("requires Linux with BlueZ");
        var engine = new CheckEngine(FakeScopeGuard.Allowing());

        var runs = await engine.RunAsync(
            [FakeCheck.Returning("MAIL-SPF-001", TargetKind.Domain, executed), FakeCheck.Returning("BT-SCAN-001", TargetKind.Domain, skipped)],
            Individual,
            Make.Scope(Domain),
            TestContext.Current.CancellationToken);

        Assert.Same(executed, runs[0].Result);
        Assert.Same(skipped, runs[1].Result);
    }

    [Fact]
    public async Task RunAsync_WhenCheckIsPassive_ShouldNotAskTheScopeGuard()
    {
        var guard = FakeScopeGuard.Denying();

        var runs = await new CheckEngine(guard).RunAsync(
            [FakeCheck.Returning("MAIL-SPF-001", TargetKind.Domain, Nothing)], Individual, Make.Scope(Domain), TestContext.Current.CancellationToken);

        Assert.Equal(0, guard.Calls);
        Assert.IsType<CheckResult.Executed>(runs[0].Result);
    }

    [Fact]
    public async Task RunAsync_WhenActiveCheckIsAuthorized_ShouldRunIt()
    {
        var guard = FakeScopeGuard.Allowing();
        var check = FakeCheck.Returning("WEB-FILES-001", TargetKind.Domain, Nothing, ScopeRequirement.ActiveOwnedOnly);

        var runs = await new CheckEngine(guard).RunAsync([check], Individual, Make.Scope(Domain), TestContext.Current.CancellationToken);

        Assert.Equal(1, guard.Calls);
        Assert.Equal(1, check.Calls);
        Assert.Same(Nothing, runs[0].Result);
    }

    [Fact]
    public async Task RunAsync_WhenActiveCheckIsNotAuthorized_ShouldSkipItWithoutRunningIt()
    {
        using var _ = new UiCulture("en-US");
        var check = FakeCheck.Returning("WEB-FILES-001", TargetKind.Domain, Nothing, ScopeRequirement.ActiveOwnedOnly);

        var runs = await new CheckEngine(FakeScopeGuard.Denying()).RunAsync([check], Individual, Make.Scope(Domain), TestContext.Current.CancellationToken);

        Assert.Equal(0, check.Calls);
        var skipped = Assert.IsType<CheckResult.Skipped>(runs[0].Result);
        Assert.StartsWith("Skipped: the target is outside the verified scope.", skipped.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task RunAsync_WhenActiveCheckIsNotAuthorizedInItalian_ShouldExplainInItalian()
    {
        using var _ = new UiCulture("it-IT");
        var check = FakeCheck.Returning("WEB-FILES-001", TargetKind.Domain, Nothing, ScopeRequirement.ActiveOwnedOnly);

        var runs = await new CheckEngine(FakeScopeGuard.Denying()).RunAsync([check], Individual, Make.Scope(Domain), TestContext.Current.CancellationToken);

        var skipped = Assert.IsType<CheckResult.Skipped>(runs[0].Result);
        Assert.StartsWith("Saltato: l'obiettivo è fuori dal perimetro verificato.", skipped.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task RunAsync_WhenScopeGuardThrows_ShouldDenyAndNotRunTheCheck()
    {
        using var _ = new UiCulture("en-US");
        var guard = new FakeScopeGuard((_, _) => throw new InvalidOperationException("DNS unreachable"));
        var check = FakeCheck.Returning("WEB-FILES-001", TargetKind.Domain, Nothing, ScopeRequirement.ActiveOwnedOnly);

        var runs = await new CheckEngine(guard).RunAsync([check], Individual, Make.Scope(Domain), TestContext.Current.CancellationToken);

        Assert.Equal(0, check.Calls);
        var skipped = Assert.IsType<CheckResult.Skipped>(runs[0].Result);
        Assert.Equal("Skipped: the ownership of the target could not be verified (DNS unreachable).", skipped.Reason);
    }

    [Fact(Timeout = 10_000)]
    public async Task RunAsync_WhenScopeGuardNeverAnswers_ShouldSkipAsUnverifiedAndNotRunTheCheck()
    {
        using var _ = new UiCulture("en-US");
        // Rude like a real hung network call: it ignores the cancellation token.
        var guard = new FakeScopeGuard((_, _) => new TaskCompletionSource<bool>().Task);
        var check = FakeCheck.Returning("WEB-FILES-001", TargetKind.Domain, Nothing, ScopeRequirement.ActiveOwnedOnly);
        var engine = new CheckEngine(guard, new CheckEngineOptions { CheckTimeout = TimeSpan.FromMilliseconds(100) });

        var runs = await engine.RunAsync([check], Individual, Make.Scope(Domain), TestContext.Current.CancellationToken);

        Assert.Equal(0, check.Calls);
        var skipped = Assert.IsType<CheckResult.Skipped>(runs[0].Result);
        Assert.Equal("Skipped: the ownership of the target could not be verified within 0.1 seconds.", skipped.Reason);
    }

    [Fact]
    public async Task RunAsync_WhenCheckThrows_ShouldReportFailedAndRunTheOthers()
    {
        using var _ = new UiCulture("en-US");
        var broken = new FakeCheck("MAIL-SPF-001", TargetKind.Domain, (_, _) => throw new InvalidOperationException("boom"));
        var fine = FakeCheck.Returning("MAIL-DMARC-001", TargetKind.Domain, Nothing);

        var runs = await new CheckEngine(FakeScopeGuard.Allowing()).RunAsync([broken, fine], Individual, Make.Scope(Domain), TestContext.Current.CancellationToken);

        var failed = Assert.IsType<CheckResult.Failed>(runs[0].Result);
        Assert.Equal("Unexpected error: boom", failed.Error);
        Assert.Same(Nothing, runs[1].Result);
    }

    [Fact]
    public async Task RunAsync_WhenCheckFaultsAsynchronously_ShouldReportFailed()
    {
        using var _ = new UiCulture("en-US");
        var broken = new FakeCheck("MAIL-SPF-001", TargetKind.Domain, async (_, _) =>
        {
            await Task.Yield();
            throw new IOException("socket closed");
        });

        var runs = await new CheckEngine(FakeScopeGuard.Allowing()).RunAsync([broken], Individual, Make.Scope(Domain), TestContext.Current.CancellationToken);

        Assert.Equal("Unexpected error: socket closed", Assert.IsType<CheckResult.Failed>(runs[0].Result).Error);
    }

    [Fact]
    public async Task RunAsync_WhenCheckReturnsNull_ShouldReportFailed()
    {
        using var _ = new UiCulture("en-US");
        var check = new FakeCheck("MAIL-SPF-001", TargetKind.Domain, (_, _) => Task.FromResult<CheckResult>(null!));

        var runs = await new CheckEngine(FakeScopeGuard.Allowing()).RunAsync([check], Individual, Make.Scope(Domain), TestContext.Current.CancellationToken);

        Assert.Equal("The check returned no result.", Assert.IsType<CheckResult.Failed>(runs[0].Result).Error);
    }

    [Fact(Timeout = 10_000)]
    public async Task RunAsync_WhenCheckIgnoresItsTokenAndHangs_ShouldStillTimeOut()
    {
        using var _ = new UiCulture("it-IT");
        var hung = new FakeCheck("MAIL-SPF-001", TargetKind.Domain, (_, _) => new TaskCompletionSource<CheckResult>().Task);
        var engine = new CheckEngine(FakeScopeGuard.Allowing(), new CheckEngineOptions { CheckTimeout = TimeSpan.FromMilliseconds(100) });

        var runs = await engine.RunAsync([hung], Individual, Make.Scope(Domain), TestContext.Current.CancellationToken);

        Assert.Equal("Il controllo non è terminato entro 0,1 secondi.", Assert.IsType<CheckResult.Failed>(runs[0].Result).Error);
    }

    [Fact(Timeout = 10_000)]
    public async Task RunAsync_WhenCheckHonoursItsTokenOnTimeout_ShouldReportTimeout()
    {
        using var _ = new UiCulture("en-US");
        var polite = new FakeCheck("MAIL-SPF-001", TargetKind.Domain, async (_, token) =>
        {
            await Task.Delay(Timeout.Infinite, token);
            return Nothing;
        });
        var engine = new CheckEngine(FakeScopeGuard.Allowing(), new CheckEngineOptions { CheckTimeout = TimeSpan.FromMilliseconds(50) });

        var runs = await engine.RunAsync([polite], Individual, Make.Scope(Domain), TestContext.Current.CancellationToken);

        Assert.Equal("The check did not finish within 0.05 seconds.", Assert.IsType<CheckResult.Failed>(runs[0].Result).Error);
    }

    [Fact(Timeout = 10_000)]
    public async Task RunAsync_WhenCallerCancels_ShouldPropagateTheCancellation()
    {
        using var cts = new CancellationTokenSource();
        var started = new TaskCompletionSource();
        var check = new FakeCheck("MAIL-SPF-001", TargetKind.Domain, async (_, token) =>
        {
            started.SetResult();
            await Task.Delay(Timeout.Infinite, token);
            return Nothing;
        });

        var run = new CheckEngine(FakeScopeGuard.Allowing()).RunAsync([check], Individual, Make.Scope(Domain), cts.Token);
        await started.Task.WaitAsync(TestContext.Current.CancellationToken);
        await cts.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => run);
    }

    [Fact(Timeout = 10_000)]
    public async Task RunAsync_WhenCallerCancelsDuringScopeVerification_ShouldPropagateTheCancellation()
    {
        using var cts = new CancellationTokenSource();
        var asked = new TaskCompletionSource();
        var guard = new FakeScopeGuard(async (_, token) =>
        {
            asked.SetResult();
            await Task.Delay(Timeout.Infinite, token);
            return true;
        });
        var check = FakeCheck.Returning("WEB-FILES-001", TargetKind.Domain, Nothing, ScopeRequirement.ActiveOwnedOnly);

        var run = new CheckEngine(guard).RunAsync([check], Individual, Make.Scope(Domain), cts.Token);
        await asked.Task.WaitAsync(TestContext.Current.CancellationToken);
        await cts.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => run);
        Assert.Equal(0, check.Calls);
    }

    [Fact]
    public async Task RunAsync_WhenAlreadyCancelled_ShouldNotRunAnyCheck()
    {
        var check = FakeCheck.Returning("MAIL-SPF-001", TargetKind.Domain, Nothing);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => new CheckEngine(FakeScopeGuard.Allowing()).RunAsync([check], Individual, Make.Scope(Domain), new CancellationToken(true)));
        Assert.Equal(0, check.Calls);
    }

    [Fact(Timeout = 10_000)]
    public async Task RunAsync_WhenManyChecks_ShouldNeverExceedTheConcurrencyLimit()
    {
        var running = 0;
        var peak = 0;
        var checks = Enumerable.Range(1, 12).Select(i => new FakeCheck($"MAIL-SPF-{i:000}", TargetKind.Domain, async (_, _) =>
        {
            var now = Interlocked.Increment(ref running);
            InterlockedMax(ref peak, now);
            await Task.Delay(20);
            Interlocked.Decrement(ref running);
            return Nothing;
        })).ToArray();
        var engine = new CheckEngine(FakeScopeGuard.Allowing(), new CheckEngineOptions { MaxConcurrentChecks = 3 });

        var runs = await engine.RunAsync(checks, Individual, Make.Scope(Domain), TestContext.Current.CancellationToken);

        Assert.Equal(12, runs.Count);
        Assert.InRange(peak, 2, 3);
        Assert.Equal(checks.Select(c => c.Id), runs.Select(r => r.CheckId));
    }

    [Fact]
    public async Task RunAsync_WhenNoCheckMatches_ShouldReturnEmpty()
    {
        var runs = await new CheckEngine(FakeScopeGuard.Allowing()).RunAsync(
            [FakeCheck.Returning("NET-PORT-001", TargetKind.Network, Nothing)], Individual, Make.Scope(Domain), TestContext.Current.CancellationToken);

        Assert.Empty(runs);
    }

    [Theory]
    [InlineData("mail-spf-001")]
    [InlineData("MAIL-SPF-001\n")]
    [InlineData("")]
    public async Task RunAsync_WhenACheckIdIsMalformed_ShouldThrowBeforeRunningAnything(string id)
    {
        var good = FakeCheck.Returning("MAIL-DMARC-001", TargetKind.Domain, Nothing);
        var bad = FakeCheck.Returning(id, TargetKind.Domain, Nothing);

        await Assert.ThrowsAsync<ArgumentException>(
            () => new CheckEngine(FakeScopeGuard.Allowing()).RunAsync([good, bad], Individual, Make.Scope(Domain), TestContext.Current.CancellationToken));
        Assert.Equal(0, good.Calls);
    }

    [Fact]
    public async Task RunAsync_WhenTwoChecksShareAnId_ShouldThrow()
    {
        var first = FakeCheck.Returning("MAIL-SPF-001", TargetKind.Domain, Nothing);
        var second = FakeCheck.Returning("MAIL-SPF-001", TargetKind.Network, Nothing);

        await Assert.ThrowsAsync<ArgumentException>(
            () => new CheckEngine(FakeScopeGuard.Allowing()).RunAsync([first, second], Individual, Make.Scope(Domain), TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task RunAsync_WhenACheckPropertyThrows_ShouldThrowBeforeRunningAnything()
    {
        var good = FakeCheck.Returning("MAIL-DMARC-001", TargetKind.Domain, Nothing);

        var error = await Assert.ThrowsAsync<ArgumentException>(
            () => new CheckEngine(FakeScopeGuard.Allowing()).RunAsync([good, new BrokenCheck()], Individual, Make.Scope(Domain), TestContext.Current.CancellationToken));

        Assert.IsType<InvalidOperationException>(error.InnerException);
        Assert.Equal(0, good.Calls);
    }

    [Fact]
    public async Task RunAsync_WhenScopeRequirementIsUndefined_ShouldThrowInsteadOfGuessing()
    {
        var check = FakeCheck.Returning("WEB-FILES-001", TargetKind.Domain, Nothing, (ScopeRequirement)99);

        await Assert.ThrowsAsync<ArgumentException>(
            () => new CheckEngine(FakeScopeGuard.Allowing()).RunAsync([check], Individual, Make.Scope(Domain), TestContext.Current.CancellationToken));
        Assert.Equal(0, check.Calls);
    }

    [Fact]
    public async Task RunAsync_WhenTargetKindIsUndefined_ShouldThrow()
    {
        var check = FakeCheck.Returning("WEB-FILES-001", (TargetKind)99, Nothing);

        await Assert.ThrowsAsync<ArgumentException>(
            () => new CheckEngine(FakeScopeGuard.Allowing()).RunAsync([check], Individual, Make.Scope(Domain), TestContext.Current.CancellationToken));
    }

    [Fact(Timeout = 10_000)]
    public async Task RunAsync_WhenTimedOutChecksKeepRunning_ShouldStillRespectTheConcurrencyLimit()
    {
        var running = 0;
        var peak = 0;
        // Rude checks: they ignore their token and run longer than the timeout, but less than timeout + grace.
        var checks = Enumerable.Range(1, 3).Select(i => new FakeCheck($"NET-PORT-{i:000}", TargetKind.Domain, async (_, _) =>
        {
            InterlockedMax(ref peak, Interlocked.Increment(ref running));
            await Task.Delay(300);
            Interlocked.Decrement(ref running);
            return Nothing;
        })).ToArray();
        var engine = new CheckEngine(
            FakeScopeGuard.Allowing(),
            new CheckEngineOptions { MaxConcurrentChecks = 1, CheckTimeout = TimeSpan.FromMilliseconds(200) });

        var runs = await engine.RunAsync(checks, Individual, Make.Scope(Domain), TestContext.Current.CancellationToken);
        await Task.Delay(400, TestContext.Current.CancellationToken);

        Assert.All(runs, r => Assert.IsType<CheckResult.Failed>(r.Result));
        Assert.Equal(1, peak);
        Assert.Equal(3, checks.Sum(c => c.Calls));
    }

    [Fact(Timeout = 10_000)]
    public async Task RunAsync_WhenACheckNeverEnds_ShouldGiveItsSlotBackAfterTheGracePeriod()
    {
        var hung = new FakeCheck("NET-PORT-001", TargetKind.Domain, (_, _) => new TaskCompletionSource<CheckResult>().Task);
        var next = FakeCheck.Returning("NET-PORT-002", TargetKind.Domain, Nothing);
        var engine = new CheckEngine(
            FakeScopeGuard.Allowing(),
            new CheckEngineOptions { MaxConcurrentChecks = 1, CheckTimeout = TimeSpan.FromMilliseconds(100) });

        var runs = await engine.RunAsync([hung, next], Individual, Make.Scope(Domain), TestContext.Current.CancellationToken);

        Assert.IsType<CheckResult.Failed>(runs[0].Result);
        Assert.Same(Nothing, runs[1].Result);
    }

    [Fact]
    public async Task RunAsync_WhenCheckCancelsByItself_ShouldReportItsOwnErrorNotAnEngineTimeout()
    {
        using var _ = new UiCulture("en-US");
        var check = new FakeCheck("WEB-TLS-001", TargetKind.Domain, (_, _) =>
            Task.FromException<CheckResult>(new TaskCanceledException("HttpClient.Timeout of 100 seconds elapsed")));

        var runs = await new CheckEngine(FakeScopeGuard.Allowing()).RunAsync([check], Individual, Make.Scope(Domain), TestContext.Current.CancellationToken);

        Assert.Equal("Unexpected error: HttpClient.Timeout of 100 seconds elapsed", Assert.IsType<CheckResult.Failed>(runs[0].Result).Error);
    }

    [Fact]
    public async Task RunAsync_WhenScopeGuardCancelsByItself_ShouldDenyAsUnverified()
    {
        using var _ = new UiCulture("en-US");
        var guard = new FakeScopeGuard((_, _) => Task.FromException<bool>(new TaskCanceledException("DNS query canceled")));
        var check = FakeCheck.Returning("WEB-FILES-001", TargetKind.Domain, Nothing, ScopeRequirement.ActiveOwnedOnly);

        var runs = await new CheckEngine(guard).RunAsync([check], Individual, Make.Scope(Domain), TestContext.Current.CancellationToken);

        Assert.Equal(0, check.Calls);
        Assert.Equal(
            "Skipped: the ownership of the target could not be verified (DNS query canceled).",
            Assert.IsType<CheckResult.Skipped>(runs[0].Result).Reason);
    }

    [Fact(Timeout = 10_000)]
    public async Task RunAsync_WhenScopeGuardHonoursTheTimeout_ShouldSkipAndRunTheNextCheckRightAway()
    {
        using var _ = new UiCulture("en-US");
        var guard = new FakeScopeGuard(async (target, token) =>
        {
            if (target == Domain)
            {
                await Task.Delay(Timeout.Infinite, token);
            }

            return true;
        });
        var check = FakeCheck.Returning("WEB-FILES-001", TargetKind.Domain, Nothing, ScopeRequirement.ActiveOwnedOnly);
        var engine = new CheckEngine(guard, new CheckEngineOptions { MaxConcurrentChecks = 1, CheckTimeout = TimeSpan.FromMilliseconds(100) });

        var runs = await engine.RunAsync([check], Individual, Make.Scope(Domain, OtherDomain), TestContext.Current.CancellationToken);

        Assert.Equal(
            "Skipped: the ownership of the target could not be verified within 0.1 seconds.",
            Assert.IsType<CheckResult.Skipped>(runs[0].Result).Reason);
        Assert.Same(Nothing, runs[1].Result);
        Assert.Equal([OtherDomain], check.SeenTargets);
    }

    [Fact]
    public async Task RunAsync_WhenScopeGuardReturnsNoTask_ShouldDeny()
    {
        var guard = new FakeScopeGuard((_, _) => null!);
        var check = FakeCheck.Returning("WEB-FILES-001", TargetKind.Domain, Nothing, ScopeRequirement.ActiveOwnedOnly);

        var runs = await new CheckEngine(guard).RunAsync([check], Individual, Make.Scope(Domain), TestContext.Current.CancellationToken);

        Assert.Equal(0, check.Calls);
        Assert.IsType<CheckResult.Skipped>(runs[0].Result);
    }

    [Fact]
    public async Task RunAsync_WhenScopeGuardAnswersDifferentlyPerTarget_ShouldAskForEachTarget()
    {
        var guard = new FakeScopeGuard((target, _) => Task.FromResult(target == Domain));
        var check = FakeCheck.Returning("WEB-FILES-001", TargetKind.Domain, Nothing, ScopeRequirement.ActiveOwnedOnly);

        var runs = await new CheckEngine(guard).RunAsync([check], Individual, Make.Scope(Domain, OtherDomain), TestContext.Current.CancellationToken);

        Assert.Equal(2, guard.Calls);
        Assert.Equal([Domain], check.SeenTargets);
        Assert.Same(Nothing, runs[0].Result);
        Assert.IsType<CheckResult.Skipped>(runs[1].Result);
    }

    private static void InterlockedMax(ref int target, int value)
    {
        int current;
        while ((current = Volatile.Read(ref target)) < value &&
               Interlocked.CompareExchange(ref target, value, current) != current)
        {
        }
    }
}
