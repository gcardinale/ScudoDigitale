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

namespace ScudoDigitale.Compliance;

/// <summary>Estimated position of a company under NIS2 (D.Lgs. 138/2024, art. 3 and 6).</summary>
public enum Nis2Outcome
{
    /// <summary>Annex I sector and above the thresholds of a medium enterprise (art. 6, paragraph 1, letter a).</summary>
    ProbablyEssential,

    /// <summary>Annex I sector as a medium enterprise, or Annex II sector above the thresholds of a small one (art. 6, paragraph 3).</summary>
    ProbablyImportant,

    /// <summary>In scope whatever its size (art. 3, paragraph 5), or in scope with a size that does not settle the category.</summary>
    ProbablyInScope,

    /// <summary>Not in a sector of Annexes I-II, or a small enterprise.</summary>
    ProbablyOutOfScope,

    /// <summary>An answer that decides the outcome is missing or "don't know".</summary>
    ToBeVerified,
}

/// <summary>
/// Estimates the NIS2 scope from the answers to the scope questions of the NIS2 questionnaire:
/// sector (Annexes I and II), the categories of art. 3, paragraph 5 that apply whatever the size, and
/// the size of the enterprise as Recommendation 2003/361/CE defines it (headcount, turnover and
/// balance sheet total). Linked enterprises, and the entities ACN identifies case by case
/// (art. 3, paragraphs 8-10), are beyond what a questionnaire can settle: the finding says so.
/// </summary>
public static class Nis2Scope
{
    /// <summary>Id of the sector question.</summary>
    public const string SectorQuestion = "NIS2-SECTOR-001";

    /// <summary>Id of the question on the categories in scope whatever their size.</summary>
    public const string SpecialQuestion = "NIS2-SPECIAL-001";

    /// <summary>Id of the headcount question.</summary>
    public const string EmployeesQuestion = "NIS2-EMPLOYEES-001";

    /// <summary>Id of the turnover question.</summary>
    public const string TurnoverQuestion = "NIS2-TURNOVER-001";

    /// <summary>Id of the balance sheet question.</summary>
    public const string BalanceQuestion = "NIS2-BALANCE-001";

    /// <summary>Prefix of the options of a sector of Annex I.</summary>
    public const string AnnexIPrefix = "annex1-";

    /// <summary>Prefix of the options of a sector of Annex II.</summary>
    public const string AnnexIIPrefix = "annex2-";

    /// <summary>Option of the sector question: none of the sectors.</summary>
    public const string NoSector = "none";

    /// <summary>The questions the scope is assessed from.</summary>
    public static IReadOnlyList<string> Questions { get; } = [SectorQuestion, SpecialQuestion, EmployeesQuestion, TurnoverQuestion, BalanceQuestion];

    /// <summary>Estimates the scope.</summary>
    /// <param name="answers">Answers by question id; a missing answer counts as "don't know".</param>
    /// <returns>The outcome.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="answers"/> is <see langword="null"/>.</exception>
    public static Nis2Outcome Assess(IReadOnlyDictionary<string, string> answers)
    {
        ArgumentNullException.ThrowIfNull(answers);
        var special = answers.GetValueOrDefault(SpecialQuestion);
        var sector = answers.GetValueOrDefault(SectorQuestion);

        if (special == Answers.Yes)
        {
            return Nis2Outcome.ProbablyInScope;
        }

        var bySector = sector switch
        {
            NoSector => Nis2Outcome.ProbablyOutOfScope,
            not null when sector.StartsWith(AnnexIPrefix, StringComparison.Ordinal) => AnnexI(answers),
            not null when sector.StartsWith(AnnexIIPrefix, StringComparison.Ordinal) => AnnexII(answers),
            _ => Nis2Outcome.ToBeVerified,
        };

        // "Out of scope" needs a clear "no" to the categories that are in scope whatever their size.
        return bySector == Nis2Outcome.ProbablyOutOfScope && special != Answers.No ? Nis2Outcome.ToBeVerified : bySector;
    }

    /// <summary>Whether the obligations are asked: always, except when the company is probably out of scope.</summary>
    /// <param name="outcome">The outcome.</param>
    /// <returns><see langword="true"/> unless <see cref="Nis2Outcome.ProbablyOutOfScope"/>.</returns>
    public static bool AsksObligations(Nis2Outcome outcome) => outcome != Nis2Outcome.ProbablyOutOfScope;

    /// <summary>Whether the enterprise is above the thresholds of a small enterprise (art. 2(2) of the Recommendation).</summary>
    /// <param name="answers">The answers.</param>
    /// <returns><see langword="true"/>, <see langword="false"/>, or <see langword="null"/> when the answers do not settle it.</returns>
    internal static bool? AboveSmall(IReadOnlyDictionary<string, string> answers)
    {
        var employees = answers.GetValueOrDefault(EmployeesQuestion);
        var turnover = answers.GetValueOrDefault(TurnoverQuestion);
        var balance = answers.GetValueOrDefault(BalanceQuestion);

        // Small: fewer than 50 persons AND turnover or balance sheet total not above 10 million.
        if (employees is "from50to249" or "from250")
        {
            return true;
        }

        var turnoverAbove10 = turnover switch { "upTo10m" => false, "upTo50m" or "over50m" => true, _ => (bool?)null };
        var balanceAbove10 = balance switch { "upTo10m" => false, "upTo43m" or "over43m" => true, _ => (bool?)null };
        if (turnoverAbove10 == true && balanceAbove10 == true)
        {
            return true;
        }

        return employees == "under50" && (turnoverAbove10 == false || balanceAbove10 == false) ? false : null;
    }

    /// <summary>Whether the enterprise is above the thresholds of a medium enterprise (art. 2(1) of the Recommendation).</summary>
    /// <param name="answers">The answers.</param>
    /// <returns><see langword="true"/>, <see langword="false"/>, or <see langword="null"/> when the answers do not settle it.</returns>
    internal static bool? AboveMedium(IReadOnlyDictionary<string, string> answers)
    {
        var employees = answers.GetValueOrDefault(EmployeesQuestion);
        var turnover = answers.GetValueOrDefault(TurnoverQuestion);
        var balance = answers.GetValueOrDefault(BalanceQuestion);

        // An SME: fewer than 250 persons AND turnover not above 50 million OR balance sheet total not above 43 million.
        if (employees == "from250")
        {
            return true;
        }

        var turnoverAbove50 = turnover switch { "upTo10m" or "upTo50m" => false, "over50m" => true, _ => (bool?)null };
        var balanceAbove43 = balance switch { "upTo10m" or "upTo43m" => false, "over43m" => true, _ => (bool?)null };
        if (turnoverAbove50 == true && balanceAbove43 == true)
        {
            return true;
        }

        return employees is "under50" or "from50to249" && (turnoverAbove50 == false || balanceAbove43 == false) ? false : null;
    }

    private static Nis2Outcome AnnexI(IReadOnlyDictionary<string, string> answers) => (AboveSmall(answers), AboveMedium(answers)) switch
    {
        (_, true) => Nis2Outcome.ProbablyEssential,
        (true, false) => Nis2Outcome.ProbablyImportant,
        (false, _) => Nis2Outcome.ProbablyOutOfScope,
        (true, null) => Nis2Outcome.ProbablyInScope,
        _ => Nis2Outcome.ToBeVerified,
    };

    private static Nis2Outcome AnnexII(IReadOnlyDictionary<string, string> answers) => AboveSmall(answers) switch
    {
        true => Nis2Outcome.ProbablyImportant,
        false => Nis2Outcome.ProbablyOutOfScope,
        null => Nis2Outcome.ToBeVerified,
    };
}

/// <summary>The answers to a yes/no question, as written in an answers file.</summary>
public static class Answers
{
    /// <summary>Yes.</summary>
    public const string Yes = "yes";

    /// <summary>No.</summary>
    public const string No = "no";

    /// <summary>Don't know.</summary>
    public const string Unknown = "unknown";

    /// <summary>Not applicable, where the question allows it.</summary>
    public const string NotApplicable = "notApplicable";
}
