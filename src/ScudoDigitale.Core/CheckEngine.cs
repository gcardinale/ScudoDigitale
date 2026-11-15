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

using System.Globalization;
using ScudoDigitale.Core.Resources;

namespace ScudoDigitale.Core;

/// <summary>
/// Runs checks against the targets of a <see cref="ScopeDeclaration"/>: matches each check to the
/// targets of its kind, enforces <see cref="IScopeGuard"/> for active checks, limits concurrency
/// and duration, and turns every failure into a <see cref="CheckResult"/> so one check can never
/// stop the others.
/// </summary>
public sealed class CheckEngine
{
    private readonly IScopeGuard scopeGuard;
    private readonly CheckEngineOptions options;

    /// <summary>
    /// Creates the engine.
    /// </summary>
    /// <param name="scopeGuard">Decides whether active checks may touch a target.</param>
    /// <param name="options">Concurrency and timeout limits; cautious defaults when <see langword="null"/>.</param>
    /// <exception cref="ArgumentNullException"><paramref name="scopeGuard"/> is <see langword="null"/>.</exception>
    public CheckEngine(IScopeGuard scopeGuard, CheckEngineOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(scopeGuard);
        this.scopeGuard = scopeGuard;
        this.options = options ?? new CheckEngineOptions();
    }

    /// <summary>
    /// Runs every check against every declared target of the kind it applies to.
    /// </summary>
    /// <remarks>
    /// The check definitions are validated before anything runs: a definition error is a programming
    /// error and stops the call. Once running, a failing check never stops the others.
    /// A check that does not stop when it times out keeps its concurrency slot until it really ends,
    /// for at most another <see cref="CheckEngineOptions.CheckTimeout"/>, so the limit protects
    /// fragile devices also from slow checks. Such a check may still be running when this method
    /// returns; its late result is ignored.
    /// </remarks>
    /// <param name="checks">The checks to run.</param>
    /// <param name="profile">Profile of whoever the assessment is for.</param>
    /// <param name="scope">Declared operator and targets.</param>
    /// <param name="cancellationToken">Stops the whole run; the cancellation is propagated to the caller.</param>
    /// <returns>One <see cref="CheckRun"/> per (target, check) pair, in target order and then check order.</returns>
    /// <exception cref="ArgumentNullException">An argument, or one of the checks, is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">
    /// A check cannot describe itself (a property throws), has an id not in the <c>AREA-TOPIC-NNN</c> form,
    /// a blank title, an undefined enum value, or the same id as another check.
    /// </exception>
    /// <exception cref="OperationCanceledException"><paramref name="cancellationToken"/> was cancelled.</exception>
    public async Task<IReadOnlyList<CheckRun>> RunAsync(
        IEnumerable<ICheck> checks,
        Profile profile,
        ScopeDeclaration scope,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(checks);
        ArgumentNullException.ThrowIfNull(profile);
        ArgumentNullException.ThrowIfNull(scope);
        var descriptors = Describe(checks.ToArray(), nameof(checks));

        var work = (
            from target in scope.Targets
            from check in descriptors
            where check.AppliesTo == target.Kind
            select (check, context: new CheckContext(target, profile, scope))).ToArray();

        // Not disposed on purpose: a timed-out check that is still running releases its slot after
        // this method has returned (see ReleaseWhenFinishedAsync). SemaphoreSlim needs no disposal
        // unless its wait handle is used.
        var gate = new SemaphoreSlim(options.MaxConcurrentChecks);
        var tasks = work.Select(w => RunGatedAsync(w.check, w.context, gate, cancellationToken));
        return await Task.WhenAll(tasks).ConfigureAwait(false);
    }

    private static CheckDescriptor[] Describe(ICheck[] checks, string parameterName)
    {
        var ids = new HashSet<string>(StringComparer.Ordinal);
        var descriptors = new CheckDescriptor[checks.Length];
        for (var i = 0; i < checks.Length; i++)
        {
            var check = checks[i] ?? throw new ArgumentNullException(parameterName, "A check is null.");
            CheckDescriptor descriptor;
            try
            {
                descriptor = new CheckDescriptor(check, check.Id, check.Title, check.Area, check.AppliesTo, check.Scope);
            }
            catch (Exception ex)
            {
                throw new ArgumentException($"The check {check.GetType().FullName} cannot describe itself.", parameterName, ex);
            }

            if (!Finding.IsCheckId(descriptor.Id))
            {
                throw new ArgumentException($"'{descriptor.Id}' ({check.GetType().FullName}) is not a check id in the AREA-TOPIC-NNN form.", parameterName);
            }

            if (string.IsNullOrWhiteSpace(descriptor.Title))
            {
                throw new ArgumentException($"The check {descriptor.Id} has no title.", parameterName);
            }

            if (!Enum.IsDefined(descriptor.Area) || !Enum.IsDefined(descriptor.AppliesTo) || !Enum.IsDefined(descriptor.Scope))
            {
                throw new ArgumentException($"The check {descriptor.Id} declares an undefined area, target kind or scope.", parameterName);
            }

            if (!ids.Add(descriptor.Id))
            {
                throw new ArgumentException($"Two checks have the id {descriptor.Id}.", parameterName);
            }

            descriptors[i] = descriptor;
        }

        return descriptors;
    }

    private async Task<CheckRun> RunGatedAsync(
        CheckDescriptor check,
        CheckContext context,
        SemaphoreSlim gate,
        CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        Task? stillRunning = null;
        try
        {
            var outcome = await RunOneAsync(check, context, cancellationToken).ConfigureAwait(false);
            stillRunning = outcome.StillRunning;
            return new CheckRun(check.Id, check.Title, check.Area, context.Target, outcome.Result);
        }
        finally
        {
            if (stillRunning is null)
            {
                gate.Release();
            }
            else
            {
                _ = ReleaseWhenFinishedAsync(stillRunning, gate, options.CheckTimeout);
            }
        }
    }

    /// <summary>
    /// Keeps the slot of abandoned work until it really ends, for at most <paramref name="grace"/>,
    /// and observes its outcome so a late failure never surfaces as an unobserved exception.
    /// </summary>
    private static async Task ReleaseWhenFinishedAsync(Task stillRunning, SemaphoreSlim gate, TimeSpan grace)
    {
        try
        {
            await stillRunning.WaitAsync(grace).ConfigureAwait(false);
        }
        catch (Exception)
        {
            // The abandoned work failed, or is still running after the grace period: its result is
            // no longer wanted, only its slot.
        }
        finally
        {
            gate.Release();
        }
    }

    private async Task<Outcome> RunOneAsync(CheckDescriptor check, CheckContext context, CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(options.CheckTimeout);

        if (check.Scope != ScopeRequirement.Passive)
        {
            var denial = await VerifyScopeAsync(context.Target, timeout, cancellationToken).ConfigureAwait(false);
            if (denial is not null)
            {
                return denial;
            }
        }

        Task<CheckResult>? running = null;
        try
        {
            running = check.Check.RunAsync(context, timeout.Token);

            // WaitAsync enforces the timeout here, even if the check ignores its token.
            var result = await running.WaitAsync(timeout.Token).ConfigureAwait(false);
            return new Outcome(result ?? new CheckResult.Failed(Strings.CheckReturnedNoResult));
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (OperationCanceledException) when (timeout.IsCancellationRequested)
        {
            var timedOut = new CheckResult.Failed(Format(Strings.CheckTimedOut, options.CheckTimeout.TotalSeconds));
            return new Outcome(timedOut, running is { IsCompleted: false } ? running : null);
        }
        catch (Exception ex)
        {
            // Includes cancellations the check raised by itself, for example an HttpClient timeout.
            return new Outcome(new CheckResult.Failed(Format(Strings.CheckUnexpectedError, ex.Message)));
        }
    }

    /// <summary>
    /// Returns <see langword="null"/> when the target is authorized, otherwise the outcome to report.
    /// Any error or timeout during verification denies access: an active check never runs on doubt.
    /// </summary>
    private async Task<Outcome?> VerifyScopeAsync(
        Target target,
        CancellationTokenSource timeout,
        CancellationToken cancellationToken)
    {
        Task<bool>? verifying = null;
        try
        {
            verifying = scopeGuard.IsAuthorizedAsync(target, timeout.Token);
            var authorized = await verifying.WaitAsync(timeout.Token).ConfigureAwait(false);
            return authorized ? null : new Outcome(new CheckResult.Skipped(Strings.ScopeNotAuthorized));
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (OperationCanceledException) when (timeout.IsCancellationRequested)
        {
            var skipped = new CheckResult.Skipped(Format(Strings.ScopeVerificationTimedOut, options.CheckTimeout.TotalSeconds));
            return new Outcome(skipped, verifying is { IsCompleted: false } ? verifying : null);
        }
        catch (Exception ex)
        {
            return new Outcome(new CheckResult.Skipped(Format(Strings.ScopeVerificationFailed, ex.Message)));
        }
    }

    private static string Format(string format, object argument) =>
        string.Format(CultureInfo.CurrentCulture, format, argument);

    /// <summary>A check definition read once, so a throwing property cannot fail the run later.</summary>
    private sealed record CheckDescriptor(ICheck Check, string Id, string Title, CheckArea Area, TargetKind AppliesTo, ScopeRequirement Scope);

    /// <summary>The result to report, and the abandoned work that is still running, if any.</summary>
    private sealed record Outcome(CheckResult Result, Task? StillRunning = null);
}
