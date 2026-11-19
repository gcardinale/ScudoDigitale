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

namespace ScudoDigitale.Checks.Email.Tests;

public sealed class EmailCheckOptionsTests
{
    [Fact]
    public void Defaults_WhenCreated_ShouldBeCautious()
    {
        var options = new EmailCheckOptions();

        Assert.Equal(TimeSpan.FromSeconds(2), options.DnsTimeout);
        Assert.Equal(1, options.DnsRetries);
        Assert.Equal(4, options.MaxConcurrentDnsQueries);
        Assert.Empty(options.DkimSelectors);
        Assert.Contains("selector1", EmailCheckOptions.CommonDkimSelectors);
        Assert.Equal(EmailCheckOptions.CommonDkimSelectors.Count, EmailCheckOptions.CommonDkimSelectors.Distinct().Count());
        Assert.All(EmailCheckOptions.CommonDkimSelectors, s => Assert.True(DomainName.IsLabel(s)));
    }

    [Fact]
    public void DkimSelectors_WhenSet_ShouldBeTrimmedLowerCasedAndDeduplicated()
    {
        var options = new EmailCheckOptions { DkimSelectors = [" Mail2026 ", "mail2026", "a.b"] };

        Assert.Equal(["mail2026", "a.b"], options.DkimSelectors);
    }

    [Theory]
    [InlineData("")]
    [InlineData("  ")]
    [InlineData("bad selector")]
    [InlineData("a..b")]
    [InlineData("-x")]
    [InlineData("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]
    [InlineData(null)]
    public void DkimSelectors_WhenItemIsNotASelector_ShouldThrow(string? selector)
    {
        Assert.Throws<ArgumentException>(() => new EmailCheckOptions { DkimSelectors = [selector!] });
    }

    [Fact]
    public void DkimSelectors_WhenNull_ShouldThrow()
    {
        Assert.Throws<ArgumentNullException>(() => new EmailCheckOptions { DkimSelectors = null! });
    }

    [Theory]
    [InlineData(1)]
    [InlineData(30_000)]
    public void DnsTimeout_WhenWithinBounds_ShouldBeAccepted(int milliseconds)
    {
        Assert.Equal(milliseconds, new EmailCheckOptions { DnsTimeout = TimeSpan.FromMilliseconds(milliseconds) }.DnsTimeout.TotalMilliseconds);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(30_001)]
    public void DnsTimeout_WhenOutOfBounds_ShouldThrow(int milliseconds)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new EmailCheckOptions { DnsTimeout = TimeSpan.FromMilliseconds(milliseconds) });
    }

    [Theory]
    [InlineData(0, true)]
    [InlineData(5, true)]
    [InlineData(-1, false)]
    [InlineData(6, false)]
    public void DnsRetries_WhenSet_ShouldAcceptOnlyZeroToFive(int value, bool valid)
    {
        if (valid)
        {
            Assert.Equal(value, new EmailCheckOptions { DnsRetries = value }.DnsRetries);
        }
        else
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => new EmailCheckOptions { DnsRetries = value });
        }
    }

    [Theory]
    [InlineData(1, true)]
    [InlineData(32, true)]
    [InlineData(0, false)]
    [InlineData(33, false)]
    public void MaxConcurrentDnsQueries_WhenSet_ShouldAcceptOnlyOneToThirtyTwo(int value, bool valid)
    {
        if (valid)
        {
            Assert.Equal(value, new EmailCheckOptions { MaxConcurrentDnsQueries = value }.MaxConcurrentDnsQueries);
        }
        else
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => new EmailCheckOptions { MaxConcurrentDnsQueries = value });
        }
    }
}
