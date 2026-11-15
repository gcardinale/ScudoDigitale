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

namespace ScudoDigitale.Core;

/// <summary>
/// Declaration of who is running the assessment and what is being checked.
/// It is printed in the report.
/// </summary>
public sealed record ScopeDeclaration
{
    /// <summary>
    /// Creates a scope declaration.
    /// </summary>
    /// <param name="operatorName">Name of the person running the assessment; surrounding spaces are removed.</param>
    /// <param name="operatorRole">Declared role of that person.</param>
    /// <param name="targets">
    /// What is being checked; duplicates are removed, order is kept. May be empty for an assessment
    /// made only of questionnaires (ADR-005).
    /// </param>
    /// <param name="declaredAt">When the declaration was made.</param>
    /// <exception cref="ArgumentException"><paramref name="operatorName"/> is empty or blank, or <paramref name="declaredAt"/> is the default value.</exception>
    /// <exception cref="ArgumentNullException"><paramref name="targets"/> or one of its items is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="operatorRole"/> is not a defined value.</exception>
    public ScopeDeclaration(
        string operatorName,
        OperatorRole operatorRole,
        IEnumerable<Target> targets,
        DateTimeOffset declaredAt)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(operatorName);
        ArgumentNullException.ThrowIfNull(targets);
        if (!Enum.IsDefined(operatorRole))
        {
            throw new ArgumentOutOfRangeException(nameof(operatorRole), operatorRole, "Unknown operator role.");
        }

        if (declaredAt == default)
        {
            throw new ArgumentException("The declaration date is missing.", nameof(declaredAt));
        }

        var list = targets.ToArray();
        if (list.Any(t => t is null))
        {
            throw new ArgumentNullException(nameof(targets), "A target is null.");
        }

        OperatorName = operatorName.Trim();
        OperatorRole = operatorRole;
        Targets = list.Distinct().ToArray();
        DeclaredAt = declaredAt;
    }

    /// <summary>Name of the person running the assessment.</summary>
    public string OperatorName { get; }

    /// <summary>Declared role of that person.</summary>
    public OperatorRole OperatorRole { get; }

    /// <summary>What is being checked, without duplicates, in declaration order; empty for a questionnaire-only assessment.</summary>
    public IReadOnlyList<Target> Targets { get; }

    /// <summary>When the declaration was made.</summary>
    public DateTimeOffset DeclaredAt { get; }
}
