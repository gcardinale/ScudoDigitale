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

using ScudoDigitale.Core.Dns;

namespace ScudoDigitale.Core.Tests;

public sealed class DnsOptionsTests
{
    [Fact]
    public void Defaults_WhenCreated_ShouldAskThePublicResolversWithShortTimeouts()
    {
        var options = new DnsOptions();

        Assert.Equal(DnsSource.Public, options.Source);
        Assert.Equal(TimeSpan.FromSeconds(2), options.Timeout);
        Assert.Equal(1, options.Retries);
    }

    [Fact]
    public void Source_WhenSet_ShouldAcceptOnlyDefinedValues()
    {
        Assert.Equal(DnsSource.System, new DnsOptions { Source = DnsSource.System }.Source);
        Assert.Throws<ArgumentOutOfRangeException>(() => new DnsOptions { Source = (DnsSource)9 });
    }

    [Theory]
    [InlineData(1, true)]
    [InlineData(30_000, true)]
    [InlineData(0, false)]
    [InlineData(-1, false)]
    [InlineData(30_001, false)]
    public void Timeout_WhenSet_ShouldAcceptOnlyPositiveValuesUpToThirtySeconds(int milliseconds, bool valid)
    {
        var value = TimeSpan.FromMilliseconds(milliseconds);
        if (valid)
        {
            Assert.Equal(value, new DnsOptions { Timeout = value }.Timeout);
        }
        else
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => new DnsOptions { Timeout = value });
        }
    }

    [Theory]
    [InlineData(0, true)]
    [InlineData(5, true)]
    [InlineData(-1, false)]
    [InlineData(6, false)]
    public void Retries_WhenSet_ShouldAcceptOnlyZeroToFive(int value, bool valid)
    {
        if (valid)
        {
            Assert.Equal(value, new DnsOptions { Retries = value }.Retries);
        }
        else
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => new DnsOptions { Retries = value });
        }
    }

    [Fact]
    public void Create_WhenNoOptionsAreGiven_ShouldBuildThePublicResolverChain()
    {
        Assert.IsType<FallbackResolver>(DnsResolvers.Create());
        Assert.IsType<DnsClientResolver>(DnsResolvers.Create(new DnsOptions { Source = DnsSource.System }));
    }
}
