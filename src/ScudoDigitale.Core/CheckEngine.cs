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
    /// <param name="checks">The checks to run.</param>
    /// <param name="profile">Profile of whoever the assessment is for.</param>
    /// <param name="scope">Declared operator and targets.</param>
    /// <param name="cancellationToken">Stops the whole run; the cancellation is propagated to the caller.</param>
    /// <returns>One <see cref="CheckRun"/> per (target, check) pair, in target order and then check order.</returns>
    /// <exception cref="ArgumentNullException">An argument, or one of the checks, is <see langword="null"/>.</exception>
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
        var checkList = checks.ToArray();
        if (checkList.Any(c => c is null))
        {
            throw new ArgumentNullException(nameof(checks), "A check is null.");
        }

        var work = (
            from target in scope.Targets
            from check in checkList
            where check.AppliesTo == target.Kind
            select (check, context: new CheckContext(target, profile, scope))).ToArray();

        using var gate = new SemaphoreSlim(options.MaxConcurrentChecks);
        var tasks = work.Select(w => RunGatedAsync(w.check, w.context, gate, cancellationToken));
        return await Task.WhenAll(tasks).ConfigureAwait(false);
    }

    private async Task<CheckRun> RunGatedAsync(
        ICheck check,
        CheckContext context,
        SemaphoreSlim gate,
        CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var result = await RunOneAsync(check, context, cancellationToken).ConfigureAwait(false);
            return new CheckRun(check.Id, check.Area, context.Target, result);
        }
        finally
        {
            gate.Release();
        }
    }

    private async Task<CheckResult> RunOneAsync(ICheck check, CheckContext context, CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(options.CheckTimeout);
        try
        {
            if (check.Scope != ScopeRequirement.Passive)
            {
                var denial = await VerifyScopeAsync(context.Target, timeout.Token).ConfigureAwait(false);
                if (denial is not null)
                {
                    return denial;
                }
            }

            // WaitAsync enforces the timeout here, even if the check ignores its token.
            var result = await check.RunAsync(context, timeout.Token).WaitAsync(timeout.Token).ConfigureAwait(false);
            return result ?? new CheckResult.Failed(Strings.CheckReturnedNoResult);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (OperationCanceledException)
        {
            return new CheckResult.Failed(Format(Strings.CheckTimedOut, options.CheckTimeout.TotalSeconds));
        }
        catch (Exception ex)
        {
            return new CheckResult.Failed(Format(Strings.CheckUnexpectedError, ex.Message));
        }
    }

    /// <summary>
    /// Returns <see langword="null"/> when the target is authorized, otherwise the result to report.
    /// Any error during verification denies access: an active check never runs on doubt.
    /// </summary>
    private async Task<CheckResult?> VerifyScopeAsync(Target target, CancellationToken cancellationToken)
    {
        bool authorized;
        try
        {
            authorized = await scopeGuard.IsAuthorizedAsync(target, cancellationToken)
                .WaitAsync(cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            return new CheckResult.Skipped(Format(Strings.ScopeVerificationFailed, ex.Message));
        }

        return authorized ? null : new CheckResult.Skipped(Strings.ScopeNotAuthorized);
    }

    private static string Format(string format, object argument) =>
        string.Format(CultureInfo.CurrentCulture, format, argument);
}
