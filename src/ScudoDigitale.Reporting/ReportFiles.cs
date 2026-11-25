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
using System.Text;

namespace ScudoDigitale.Reporting;

/// <summary>
/// Writes the three files of a report (HTML, PDF, JSON) in a folder, with the same name and the time
/// of the report in it, so that two runs never overwrite each other.
/// </summary>
public static class ReportFiles
{
    /// <summary>Writes the report files.</summary>
    /// <param name="document">The report.</param>
    /// <param name="folder">Where to write them; created if missing.</param>
    /// <param name="cancellationToken">Stops between one file and the next.</param>
    /// <returns>The paths of the files written.</returns>
    /// <exception cref="ArgumentNullException">An argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="folder"/> is empty or blank.</exception>
    /// <exception cref="IOException">A file could not be written (it already exists, the disk is full, ...).</exception>
    /// <exception cref="UnauthorizedAccessException">The folder cannot be written.</exception>
    public static async Task<ReportPaths> WriteAsync(ReportDocument document, string folder, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(document);
        ArgumentException.ThrowIfNullOrWhiteSpace(folder);

        // Rendering first: a template or font problem must not leave half a report on the disk.
        var json = ReportJson.Write(document);
        var html = HtmlReport.Render(document);
        var pdf = PdfReport.Render(document);

        Directory.CreateDirectory(folder);
        var stem = Path.Combine(Path.GetFullPath(folder), BaseName(document));
        var paths = new ReportPaths(stem + ".html", stem + ".pdf", stem + ".json");

        var utf8 = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);
        await WriteNewAsync(paths.Html, utf8.GetBytes(html), cancellationToken).ConfigureAwait(false);
        await WriteNewAsync(paths.Pdf, pdf, cancellationToken).ConfigureAwait(false);
        await WriteNewAsync(paths.Json, utf8.GetBytes(json), cancellationToken).ConfigureAwait(false);
        return paths;
    }

    /// <summary>The name of the files without extension, for example <c>scudo-report-20261125-103000</c>.</summary>
    /// <param name="document">The report.</param>
    /// <returns>The name, from the local time of the report.</returns>
    public static string BaseName(ReportDocument document)
    {
        ArgumentNullException.ThrowIfNull(document);
        return "scudo-report-" + document.GeneratedAt.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture);
    }

    private static async Task WriteNewAsync(string path, byte[] bytes, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        // CreateNew: an existing report is never overwritten.
        await using var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        await stream.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
    }
}

/// <summary>Where the files of a report were written.</summary>
/// <param name="Html">The HTML file.</param>
/// <param name="Pdf">The PDF file.</param>
/// <param name="Json">The JSON file.</param>
public sealed record ReportPaths(string Html, string Pdf, string Json);
