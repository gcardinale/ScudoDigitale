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

using System.Text;

namespace ScudoDigitale.Reporting.Tests;

public sealed class ReportFilesTests : IDisposable
{
    private readonly string folder = Path.Combine(Path.GetTempPath(), "scudo-report-tests-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        if (Directory.Exists(folder))
        {
            Directory.Delete(folder, recursive: true);
        }
    }

    [Fact]
    public async Task WriteAsync_WhenFolderIsMissing_ShouldCreateItAndWriteTheThreeFiles()
    {
        var document = Make.Document();
        var nested = Path.Combine(folder, "reports");

        var paths = await ReportFiles.WriteAsync(document, nested, TestContext.Current.CancellationToken);

        Assert.Equal(Path.Combine(nested, "scudo-report-20261125-103105.html"), paths.Html);
        Assert.Equal(Path.Combine(nested, "scudo-report-20261125-103105.pdf"), paths.Pdf);
        Assert.Equal(Path.Combine(nested, "scudo-report-20261125-103105.json"), paths.Json);
        Assert.Equal(HtmlReport.Render(document), await File.ReadAllTextAsync(paths.Html, TestContext.Current.CancellationToken));
        Assert.Equal(ReportJson.Write(document), await File.ReadAllTextAsync(paths.Json, TestContext.Current.CancellationToken));
        Assert.Equal("%PDF-", Encoding.ASCII.GetString((await File.ReadAllBytesAsync(paths.Pdf, TestContext.Current.CancellationToken))[..5]));

        // No byte order mark: the JSON is read by other programs too.
        Assert.Equal((byte)'{', (await File.ReadAllBytesAsync(paths.Json, TestContext.Current.CancellationToken))[0]);
    }

    [Fact]
    public async Task WriteAsync_WhenAReportOfTheSameSecondExists_ShouldAddANumberAndNotOverwriteIt()
    {
        var document = Make.Document();
        Directory.CreateDirectory(folder);
        var existing = Path.Combine(folder, ReportFiles.BaseName(document) + ".pdf");
        await File.WriteAllTextAsync(existing, "mine", TestContext.Current.CancellationToken);

        var second = await ReportFiles.WriteAsync(document, folder, TestContext.Current.CancellationToken);
        var third = await ReportFiles.WriteAsync(document, folder, TestContext.Current.CancellationToken);

        Assert.Equal(Path.Combine(folder, "scudo-report-20261125-103105-2.html"), second.Html);
        Assert.Equal(Path.Combine(folder, "scudo-report-20261125-103105-3.json"), third.Json);
        Assert.Equal("mine", await File.ReadAllTextAsync(existing, TestContext.Current.CancellationToken));
        Assert.False(File.Exists(Path.Combine(folder, "scudo-report-20261125-103105.html")));
    }

    [Fact]
    public void FreePaths_WhenEveryNumberIsTaken_ShouldThrow()
    {
        Directory.CreateDirectory(folder);
        var stem = Path.Combine(folder, "r");
        File.WriteAllText(stem + ".json", string.Empty);
        for (var n = 2; n < 100; n++)
        {
            File.WriteAllText($"{stem}-{n}.html", string.Empty);
        }

        Assert.Throws<IOException>(() => ReportFiles.FreePaths(stem));
    }

    [Fact]
    public async Task WriteAsync_WhenAFileFailsHalfway_ShouldRemoveTheFilesAlreadyWritten()
    {
        var calls = 0;
        Task Write(string path, byte[] bytes, CancellationToken token)
        {
            // The first file is written, the second fails as a full disk would.
            if (++calls == 2)
            {
                throw new IOException("disk full");
            }

            return File.WriteAllBytesAsync(path, bytes, token);
        }

        var e = await Assert.ThrowsAsync<IOException>(() => ReportFiles.WriteAsync(Make.Document(), folder, Write, TestContext.Current.CancellationToken));

        Assert.Equal("disk full", e.Message);
        Assert.Empty(Directory.EnumerateFiles(folder));
    }

    [Fact]
    public async Task WriteAsync_WhenCancelledAfterTheFirstFile_ShouldRemoveIt()
    {
        using var cancel = new CancellationTokenSource();
        async Task Write(string path, byte[] bytes, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            await File.WriteAllBytesAsync(path, bytes, CancellationToken.None);
            await cancel.CancelAsync();
        }

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => ReportFiles.WriteAsync(Make.Document(), folder, Write, cancel.Token));

        Assert.Empty(Directory.EnumerateFiles(folder));
    }

    [Fact]
    public async Task WriteAsync_WhenCancelled_ShouldWriteNothing()
    {
        using var cancelled = new CancellationTokenSource();
        await cancelled.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => ReportFiles.WriteAsync(Make.Document(), folder, cancelled.Token));

        Assert.Empty(Directory.EnumerateFiles(folder));
    }

    [Fact]
    public async Task WriteAsync_WhenAnArgumentIsMissing_ShouldThrow()
    {
        await Assert.ThrowsAsync<ArgumentNullException>(() => ReportFiles.WriteAsync(null!, folder, TestContext.Current.CancellationToken));
        await Assert.ThrowsAsync<ArgumentException>(() => ReportFiles.WriteAsync(Make.Document(), " ", TestContext.Current.CancellationToken));
        Assert.Throws<ArgumentNullException>(() => ReportFiles.BaseName(null!));
    }
}
