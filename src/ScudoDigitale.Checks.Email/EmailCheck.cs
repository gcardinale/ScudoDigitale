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

using ScudoDigitale.Checks.Email.Resources;
using ScudoDigitale.Core;

namespace ScudoDigitale.Checks.Email;

/// <summary>
/// Evaluates one rule on a valid, existing domain.
/// </summary>
/// <param name="inspector">Shared DNS analyses of the run.</param>
/// <param name="domain">Normalized domain name.</param>
/// <param name="cancellationToken">Cancelled when the user stops the run or the check times out.</param>
/// <returns>The outcome of the rule.</returns>
internal delegate Task<CheckResult> EmailRule(EmailDomainInspector inspector, string domain, CancellationToken cancellationToken);

/// <summary>
/// A passive email check on a domain. It validates the target, stops early when the domain does not
/// exist, then runs its rule. It never throws towards the engine, except to honour cancellation.
/// </summary>
internal sealed class EmailCheck : ICheck
{
    private readonly Func<string> title;
    private readonly EmailDomainInspector inspector;
    private readonly EmailRule rule;

    /// <summary>Creates the check.</summary>
    /// <param name="id">Stable id, for example <c>MAIL-SPF-001</c>.</param>
    /// <param name="title">Reads the localized title, so it follows the current UI language.</param>
    /// <param name="inspector">Shared DNS analyses of the run.</param>
    /// <param name="rule">What the check evaluates.</param>
    public EmailCheck(string id, Func<string> title, EmailDomainInspector inspector, EmailRule rule)
    {
        Id = id;
        this.title = title;
        this.inspector = inspector;
        this.rule = rule;
    }

    /// <inheritdoc />
    public string Id { get; }

    /// <inheritdoc />
    public string Title => title();

    /// <inheritdoc />
    public CheckArea Area => CheckArea.Email;

    /// <inheritdoc />
    public TargetKind AppliesTo => TargetKind.Domain;

    /// <inheritdoc />
    public ScopeRequirement Scope => ScopeRequirement.Passive;

    /// <inheritdoc />
    public async Task<CheckResult> RunAsync(CheckContext context, CancellationToken cancellationToken)
    {
        try
        {
            var value = context.Target.Value;
            if (context.Target.Kind != TargetKind.Domain || !DomainName.TryNormalize(value, out var domain))
            {
                return new CheckResult.Failed(EmailFinding.Format(Strings.InvalidDomain, value));
            }

            var existence = await inspector.GetTxtAsync(domain, cancellationToken).ConfigureAwait(false);
            if (existence.Status == DnsStatus.NonExistentDomain)
            {
                return new CheckResult.Failed(EmailFinding.Format(Strings.DomainNotFound, domain));
            }

            return await rule(inspector, domain, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            return new CheckResult.Failed(EmailFinding.Format(Strings.UnexpectedError, ex.Message));
        }
    }
}
