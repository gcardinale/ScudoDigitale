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

namespace ScudoDigitale.Checks.Web.Tests;

public sealed class HostNameTests
{
    [Theory]
    [InlineData("example.com", "example.com")]
    [InlineData("  WWW.Example.COM.  ", "www.example.com")]
    [InlineData("https://Example.com/path?x=1", "example.com")]
    [InlineData("http://example.com", "example.com")]
    [InlineData("https://example.com:443/", "example.com")]
    [InlineData("caffè.it", "xn--caff-8oa.it")]
    public void TryNormalize_WhenValueNamesAWebsite_ShouldReturnItsLowerCaseAsciiHost(string value, string expected)
    {
        Assert.True(HostName.TryNormalize(value, out var host));
        Assert.Equal(expected, host);
        Assert.True(WebChecks.TryNormalizeTarget(value, out var same));
        Assert.Equal(expected, same);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(".")]
    [InlineData("localhost")]
    [InlineData("ftp://example.com/")]
    [InlineData("https://example.com:8443/")]
    [InlineData("https://")]
    [InlineData("example.com/path")]
    [InlineData("example.com:8080")]
    [InlineData("user@example.com")]
    [InlineData("exa mple.com")]
    [InlineData("example..com")]
    [InlineData("-example.com")]
    [InlineData("example-.com")]
    [InlineData("exa_mple.com")]
    [InlineData("192.168.1.1")]
    [InlineData("https://192.168.1.1/")]
    [InlineData("example.com\n.evil")]
    public void TryNormalize_WhenValueIsNotAWebsiteName_ShouldReturnFalse(string? value)
    {
        Assert.False(HostName.TryNormalize(value, out var host));
        Assert.Null(host);
        Assert.False(WebChecks.TryNormalizeTarget(value, out _));
    }

    [Fact]
    public void TryNormalize_WhenLengthIsAtTheLimits_ShouldAcceptOnlyNamesWithinThem()
    {
        var label63 = new string('a', 63);
        var label61 = new string('a', 61);
        var name253 = string.Join('.', label61, label61, label61, label61) + ".abcde";

        Assert.True(HostName.TryNormalize(label63 + ".com", out _));
        Assert.False(HostName.TryNormalize(label63 + "a.com", out _));
        Assert.Equal(HostName.MaxLength, name253.Length);
        Assert.True(HostName.TryNormalize(name253, out _));
        Assert.False(HostName.TryNormalize("a" + name253, out _));
    }

    [Theory]
    [InlineData("example.com", "example.com", true)]
    [InlineData("example.com", "WWW.Example.com.", true)]
    [InlineData("example.com", "shop.example.com", true)]
    [InlineData("www.example.com", "example.com", true)]
    [InlineData("example.com", "example.org", false)]
    [InlineData("example.com", "badexample.com", false)]
    [InlineData("example.com", "example.com.evil.net", false)]
    [InlineData("shop.example.com", "example.com", false)]
    [InlineData("shop.example.com", "www.example.com", false)]
    public void IsInSite_WhenCalled_ShouldAcceptOnlyTheSameNameItsWwwFormAndItsSubdomains(string site, string host, bool expected)
    {
        Assert.Equal(expected, HostName.IsInSite(site, host));
    }
}
