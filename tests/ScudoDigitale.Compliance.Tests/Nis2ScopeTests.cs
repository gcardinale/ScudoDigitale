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

namespace ScudoDigitale.Compliance.Tests;

public sealed class Nis2ScopeTests
{
    [Theory]
    // Annex I: above medium → essential; medium → important; small → out of scope.
    [InlineData("annex1-energy", "no", "from250", "unknown", "unknown", Nis2Outcome.ProbablyEssential)]
    [InlineData("annex1-energy", "no", "from50to249", "over50m", "over43m", Nis2Outcome.ProbablyEssential)]
    [InlineData("annex1-energy", "no", "from50to249", "over50m", "upTo43m", Nis2Outcome.ProbablyImportant)]
    [InlineData("annex1-energy", "no", "from50to249", "upTo50m", "unknown", Nis2Outcome.ProbablyImportant)]
    [InlineData("annex1-energy", "no", "under50", "upTo50m", "upTo43m", Nis2Outcome.ProbablyImportant)]
    [InlineData("annex1-energy", "no", "under50", "upTo10m", "over43m", Nis2Outcome.ProbablyOutOfScope)]
    [InlineData("annex1-energy", "no", "under50", "over50m", "upTo10m", Nis2Outcome.ProbablyOutOfScope)]
    // Annex I, in scope but the category is not settled: above small, medium unknown.
    [InlineData("annex1-health", "no", "from50to249", "unknown", "unknown", Nis2Outcome.ProbablyInScope)]
    // Annex I, size not settled at all.
    [InlineData("annex1-health", "no", "unknown", "unknown", "unknown", Nis2Outcome.ToBeVerified)]
    [InlineData("annex1-health", "no", "under50", "unknown", "unknown", Nis2Outcome.ToBeVerified)]
    // Headcount unknown, but turnover and balance above both medium thresholds.
    [InlineData("annex1-banking", "no", "unknown", "over50m", "over43m", Nis2Outcome.ProbablyEssential)]
    // Annex II: above small → important; small → out of scope.
    [InlineData("annex2-food", "no", "from250", "over50m", "over43m", Nis2Outcome.ProbablyImportant)]
    [InlineData("annex2-food", "no", "under50", "upTo50m", "upTo43m", Nis2Outcome.ProbablyImportant)]
    [InlineData("annex2-food", "no", "under50", "upTo10m", "upTo43m", Nis2Outcome.ProbablyOutOfScope)]
    [InlineData("annex2-food", "no", "unknown", "upTo10m", "unknown", Nis2Outcome.ToBeVerified)]
    // Sector.
    [InlineData("none", "no", "from250", "over50m", "over43m", Nis2Outcome.ProbablyOutOfScope)]
    [InlineData("unknown", "no", "from250", "over50m", "over43m", Nis2Outcome.ToBeVerified)]
    [InlineData(null, "no", "from250", "over50m", "over43m", Nis2Outcome.ToBeVerified)]
    // In scope whatever the size.
    [InlineData("none", "yes", "under50", "upTo10m", "upTo10m", Nis2Outcome.ProbablyInScope)]
    // "Out of scope" needs a clear "no" to the categories in scope whatever their size.
    [InlineData("none", "unknown", "under50", "upTo10m", "upTo10m", Nis2Outcome.ToBeVerified)]
    [InlineData("annex2-food", null, "under50", "upTo10m", "upTo10m", Nis2Outcome.ToBeVerified)]
    [InlineData("annex2-food", null, "from250", "upTo10m", "upTo10m", Nis2Outcome.ProbablyImportant)]
    public void Assess_WhenAnswersAreGiven_ShouldEstimateTheScopeAsArticles3And6(
        string? sector, string? special, string? employees, string? turnover, string? balance, Nis2Outcome expected)
    {
        var answers = Make.Answers(
            (Nis2Scope.SectorQuestion, sector),
            (Nis2Scope.SpecialQuestion, special),
            (Nis2Scope.EmployeesQuestion, employees),
            (Nis2Scope.TurnoverQuestion, turnover),
            (Nis2Scope.BalanceQuestion, balance));

        Assert.Equal(expected, Nis2Scope.Assess(answers));
    }

    [Theory]
    [InlineData(Nis2Outcome.ProbablyEssential, true)]
    [InlineData(Nis2Outcome.ProbablyImportant, true)]
    [InlineData(Nis2Outcome.ProbablyInScope, true)]
    [InlineData(Nis2Outcome.ToBeVerified, true)]
    [InlineData(Nis2Outcome.ProbablyOutOfScope, false)]
    public void AsksObligations_WhenOutcomeIsGiven_ShouldSkipThemOnlyWhenOutOfScope(Nis2Outcome outcome, bool expected)
    {
        Assert.Equal(expected, Nis2Scope.AsksObligations(outcome));
    }

    [Fact]
    public void Assess_WhenAnswersAreNull_ShouldThrow()
    {
        Assert.Throws<ArgumentNullException>(() => Nis2Scope.Assess(null!));
    }
}
