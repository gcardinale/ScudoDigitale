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
/// of the report in it; two runs never overwrite each other, and a failure leaves no half report.
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
    /// <exception cref="IOException">A file could not be written (disk full, a hundred reports with the same name, ...); the files already written are removed.</exception>
    /// <exception cref="UnauthorizedAccessException">The folder cannot be written.</exception>
    public static Task<ReportPaths> WriteAsync(ReportDocument document, string folder, CancellationToken cancellationToken = default) =>
        WriteAsync(document, folder, WriteNewAsync, cancellationToken);

    /// <summary>Writes the report files with a given way of writing one file (tests use it to make a write fail).</summary>
    /// <param name="document">The report.</param>
    /// <param name="folder">Where to write them.</param>
    /// <param name="write">Writes one new file; must not overwrite.</param>
    /// <param name="cancellationToken">Stops between one file and the next.</param>
    /// <returns>The paths of the files written.</returns>
    internal static async Task<ReportPaths> WriteAsync(
        ReportDocument document,
        string folder,
        Func<string, byte[], CancellationToken, Task> write,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(document);
        ArgumentException.ThrowIfNullOrWhiteSpace(folder);

        // Rendering first: a template or font problem must not leave half a report on the disk.
        var json = ReportJson.Write(document);
        var html = HtmlReport.Render(document);
        var pdf = PdfReport.Render(document);

        Directory.CreateDirectory(folder);
        var paths = FreePaths(Path.Combine(Path.GetFullPath(folder), BaseName(document)));

        var utf8 = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);
        var written = new List<string>();
        try
        {
            foreach (var (path, bytes) in new[] { (paths.Html, utf8.GetBytes(html)), (paths.Pdf, pdf), (paths.Json, utf8.GetBytes(json)) })
            {
                await write(path, bytes, cancellationToken).ConfigureAwait(false);
                written.Add(path);
            }
        }
        catch
        {
            // Three files or none: a half report would look complete in the folder.
            foreach (var path in written)
            {
                TryDelete(path);
            }

            throw;
        }

        return paths;
    }

    /// <summary>
    /// The paths for a report, with <c>-2</c>, <c>-3</c>… after the name when a report of the same
    /// second is already there (two runs in a script): an existing report is never overwritten.
    /// </summary>
    /// <param name="stem">Folder and base name, without extension.</param>
    /// <returns>Paths none of which exists.</returns>
    /// <exception cref="IOException">Every name up to <c>-99</c> is taken.</exception>
    internal static ReportPaths FreePaths(string stem)
    {
        for (var n = 1; n < 100; n++)
        {
            var candidate = n == 1 ? stem : $"{stem}-{n}";
            var paths = new ReportPaths(candidate + ".html", candidate + ".pdf", candidate + ".json");
            if (!Path.Exists(paths.Html) && !Path.Exists(paths.Pdf) && !Path.Exists(paths.Json))
            {
                return paths;
            }
        }

        throw new IOException($"Too many reports named {Path.GetFileName(stem)} in {Path.GetDirectoryName(stem)}.");
    }

    private static void TryDelete(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            // The error that stopped the writing is the one to report, not this one.
        }
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
