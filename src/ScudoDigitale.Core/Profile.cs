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
/// Profile of whoever the assessment is for: an individual or a company.
/// Create instances with <see cref="Individual"/> or <see cref="Company"/>.
/// </summary>
public sealed record Profile
{
    private Profile(
        ProfileKind kind,
        string? companyName,
        string? vatNumber,
        string? atecoCode,
        int? employees,
        decimal? annualTurnoverEur)
    {
        Kind = kind;
        CompanyName = companyName;
        VatNumber = vatNumber;
        AtecoCode = atecoCode;
        Employees = employees;
        AnnualTurnoverEur = annualTurnoverEur;
    }

    /// <summary>Individual or company.</summary>
    public ProfileKind Kind { get; }

    /// <summary>Company name; <see langword="null"/> for an individual.</summary>
    public string? CompanyName { get; }

    /// <summary>VAT number, optional.</summary>
    public string? VatNumber { get; }

    /// <summary>ATECO sector code (Italian classification of economic activities), optional.</summary>
    public string? AtecoCode { get; }

    /// <summary>Number of employees, if known.</summary>
    public int? Employees { get; }

    /// <summary>Annual turnover in euro, if known.</summary>
    public decimal? AnnualTurnoverEur { get; }

    /// <summary>
    /// Creates the profile of a private individual.
    /// </summary>
    /// <returns>An individual profile.</returns>
    public static Profile Individual() => new(ProfileKind.Individual, null, null, null, null, null);

    /// <summary>
    /// Creates the profile of a company.
    /// </summary>
    /// <param name="companyName">Company name; surrounding spaces are removed.</param>
    /// <param name="employees">Number of employees, if known; cannot be negative.</param>
    /// <param name="annualTurnoverEur">Annual turnover in euro, if known; cannot be negative.</param>
    /// <param name="vatNumber">VAT number, optional; blank is treated as missing.</param>
    /// <param name="atecoCode">ATECO sector code, optional; blank is treated as missing.</param>
    /// <returns>A company profile.</returns>
    /// <exception cref="ArgumentException"><paramref name="companyName"/> is empty or blank.</exception>
    /// <exception cref="ArgumentOutOfRangeException">A number is negative.</exception>
    public static Profile Company(
        string companyName,
        int? employees = null,
        decimal? annualTurnoverEur = null,
        string? vatNumber = null,
        string? atecoCode = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(companyName);
        if (employees < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(employees), employees, "Cannot be negative.");
        }

        if (annualTurnoverEur < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(annualTurnoverEur), annualTurnoverEur, "Cannot be negative.");
        }

        return new Profile(
            ProfileKind.Company,
            companyName.Trim(),
            Optional(vatNumber),
            Optional(atecoCode),
            employees,
            annualTurnoverEur);
    }

    private static string? Optional(string? value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();
}
