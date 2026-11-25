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

using PdfSharp.Fonts;

namespace ScudoDigitale.Reporting;

/// <summary>
/// Gives PdfSharp the DejaVu Sans font included in the program, whatever font a document asks for.
/// PdfSharp finds no system fonts on Linux and macOS, and on Windows the result would depend on the
/// fonts installed: with one included font the PDF is the same on every computer.
/// </summary>
internal sealed class EmbeddedFontResolver : IFontResolver
{
    /// <summary>The family name to use in documents.</summary>
    public const string Family = "DejaVu Sans";

    /// <summary>Face name of the regular font.</summary>
    internal const string RegularFace = "DejaVuSans";

    /// <summary>Face name of the bold font.</summary>
    internal const string BoldFace = "DejaVuSans-Bold";

    private static readonly Lock Gate = new();

    /// <summary>
    /// Installs the resolver for the whole process, unless the host has already installed its own:
    /// PdfSharp allows one resolver per process.
    /// </summary>
    public static void Install()
    {
        lock (Gate)
        {
            GlobalFontSettings.FontResolver ??= new EmbeddedFontResolver();
        }
    }

    /// <summary>Maps any family to DejaVu Sans; italic is simulated, as the italic face is not included.</summary>
    /// <param name="familyName">Requested family, ignored.</param>
    /// <param name="bold">Whether the bold face is wanted.</param>
    /// <param name="italic">Whether the italic face is wanted.</param>
    /// <returns>The face to use.</returns>
    public FontResolverInfo ResolveTypeface(string familyName, bool bold, bool italic) =>
        new(bold ? BoldFace : RegularFace, mustSimulateBold: false, mustSimulateItalic: italic);

    /// <summary>The bytes of a face.</summary>
    /// <param name="faceName">A face returned by <see cref="ResolveTypeface"/>.</param>
    /// <returns>The TrueType font, or <see langword="null"/> for a face that is not included.</returns>
    public byte[]? GetFont(string faceName)
    {
        if (faceName is not (RegularFace or BoldFace))
        {
            return null;
        }

        using var stream = typeof(EmbeddedFontResolver).Assembly.GetManifestResourceStream($"ScudoDigitale.Reporting.Fonts.{faceName}.ttf")
            ?? throw new InvalidOperationException($"Missing font resource {faceName}.");
        using var copy = new MemoryStream();
        stream.CopyTo(copy);
        return copy.ToArray();
    }
}
