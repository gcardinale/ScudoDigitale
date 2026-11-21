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

using ScudoDigitale.Checks.Web.Resources;
using ScudoDigitale.Core;

namespace ScudoDigitale.Checks.Web;

/// <summary>
/// A passive check on a website. It validates the target, stops early when the site cannot be
/// reached at all, then evaluates its rule on the shared visit. It never throws towards the engine,
/// except to honour cancellation.
/// </summary>
internal sealed class WebCheck : ICheck
{
    private readonly Func<string> title;
    private readonly WebSiteInspector inspector;
    private readonly Func<SiteVisit, CheckResult> rule;

    /// <summary>Creates the check.</summary>
    /// <param name="id">Stable id, for example <c>WEB-HSTS-001</c>.</param>
    /// <param name="title">Reads the localized title, so it follows the current UI language.</param>
    /// <param name="inspector">Shared visits of the run.</param>
    /// <param name="rule">What the check evaluates on a visit.</param>
    public WebCheck(string id, Func<string> title, WebSiteInspector inspector, Func<SiteVisit, CheckResult> rule)
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
    public CheckArea Area => CheckArea.Web;

    /// <inheritdoc />
    public TargetKind AppliesTo => TargetKind.Website;

    /// <inheritdoc />
    public ScopeRequirement Scope => ScopeRequirement.Passive;

    /// <inheritdoc />
    public async Task<CheckResult> RunAsync(CheckContext context, CancellationToken cancellationToken)
    {
        try
        {
            var value = context.Target.Value;
            if (context.Target.Kind != TargetKind.Website || !HostName.TryNormalize(value, out var host))
            {
                return new CheckResult.Failed(WebFinding.Format(Strings.InvalidSite, value));
            }

            var visit = await inspector.GetAsync(host, cancellationToken).ConfigureAwait(false);
            if ((visit.Http.End == TrailEnd.Error && visit.Https.End == TrailEnd.Error) || visit.Https.Unanswered || visit.Http.Unanswered)
            {
                // Nothing was observed, or a name along the way got no answer from the DNS:
                // reporting problems here would be inventing them.
                return new CheckResult.Failed(WebFinding.Format(Strings.SiteUnreachable, host, visit.Https.Error ?? visit.Http.Error));
            }

            return rule(visit);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (TimeoutException ex)
        {
            return new CheckResult.Failed(ex.Message);
        }
        catch (Exception ex)
        {
            return new CheckResult.Failed(WebFinding.Format(Strings.UnexpectedError, ex.Message));
        }
    }
}
