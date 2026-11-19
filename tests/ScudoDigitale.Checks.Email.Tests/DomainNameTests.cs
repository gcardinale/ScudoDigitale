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

public sealed class DomainNameTests
{
    [Theory]
    [InlineData("example.com", "example.com")]
    [InlineData("  Example.COM.  ", "example.com")]
    [InlineData("mail.example.co.uk", "mail.example.co.uk")]
    [InlineData("_dmarc.example.com", "_dmarc.example.com")]
    [InlineData("caffè.it", "xn--caff-8oa.it")]
    public void TryNormalize_WhenNameIsValid_ShouldReturnLowerCaseAscii(string value, string expected)
    {
        Assert.True(DomainName.TryNormalize(value, out var domain));
        Assert.Equal(expected, domain);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("localhost")]
    [InlineData("https://example.com")]
    [InlineData("example.com/path")]
    [InlineData("user@example.com")]
    [InlineData("exa mple.com")]
    [InlineData("example..com")]
    [InlineData("-example.com")]
    [InlineData("example-.com")]
    [InlineData("192.168.1.1")]
    [InlineData("2001:db8::1")]
    [InlineData("example\n.com")]
    [InlineData("example.com\n.evil")]
    public void TryNormalize_WhenNameIsNotADomain_ShouldReturnFalse(string? value)
    {
        Assert.False(DomainName.TryNormalize(value, out var domain));
        Assert.Null(domain);
    }

    [Fact]
    public void IsLabel_WhenLengthIsAtTheBounds_ShouldAcceptOneTo63Characters()
    {
        // Pinned directly: for domains IdnMapping rejects long labels by itself, but DKIM selectors
        // are validated with IsLabel alone.
        Assert.True(DomainName.IsLabel("a"));
        Assert.True(DomainName.IsLabel(new string('a', 63)));
        Assert.False(DomainName.IsLabel(new string('a', 64)));
        Assert.False(DomainName.IsLabel(string.Empty));
    }

    [Fact]
    public void TryNormalize_WhenLabelIsLongerThan63_ShouldReturnFalse()
    {
        var label63 = new string('a', 63);
        Assert.True(DomainName.TryNormalize(label63 + ".com", out _));
        Assert.False(DomainName.TryNormalize(label63 + "a.com", out _));
    }

    [Fact]
    public void TryNormalize_WhenNameIsExactlyAtTheLengthLimit_ShouldAcceptIt()
    {
        var label = new string('a', 61);
        var name = string.Join('.', label, label, label, label) + ".abcde";
        Assert.Equal(DomainName.MaxLength, name.Length);
        Assert.True(DomainName.TryNormalize(name, out _));
        Assert.False(DomainName.TryNormalize("a" + name, out _));
    }

    [Theory]
    [InlineData("mail.example.com", "example.com")]
    [InlineData("a.b.example.com", "b.example.com")]
    [InlineData("example.com", null)]
    public void Parent_WhenCalled_ShouldStopAtTwoLabels(string domain, string? expected)
    {
        Assert.Equal(expected, DomainName.Parent(domain));
    }
}
