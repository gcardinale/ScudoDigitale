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

using System.Collections;
using System.Globalization;
using System.Resources;
using System.Text.RegularExpressions;
using ScudoDigitale.Core.Resources;

namespace ScudoDigitale.Core.Tests;

public sealed class ResourcesTests
{
    [Fact]
    public void Resources_WhenComparingLanguages_ShouldHaveTheSameKeysAndPlaceholders()
    {
        var english = Read(CultureInfo.InvariantCulture);
        var italian = Read(CultureInfo.GetCultureInfo("it"));

        Assert.Equal(english.Keys.Order(), italian.Keys.Order());
        foreach (var (key, text) in english)
        {
            Assert.False(string.IsNullOrWhiteSpace(text), key);
            Assert.False(string.IsNullOrWhiteSpace(italian[key]), key);
            Assert.Equal(Placeholders(text), Placeholders(italian[key]));
        }
    }

    [Theory]
    [InlineData("NoDnsServer")]
    [InlineData("DnsNoAnswerInTime")]
    public void Resources_WhenReadingTheDnsMessages_ShouldBeTranslated(string key)
    {
        Assert.NotEqual(Read(CultureInfo.InvariantCulture)[key], Read(CultureInfo.GetCultureInfo("it"))[key]);
    }

    private static Dictionary<string, string> Read(CultureInfo culture)
    {
        var manager = new ResourceManager(typeof(Strings));
        using var set = manager.GetResourceSet(culture, createIfNotExists: true, tryParents: false)!;
        return set.Cast<DictionaryEntry>().ToDictionary(e => (string)e.Key, e => (string)e.Value!);
    }

    private static string[] Placeholders(string text) =>
        [.. Regex.Matches(text, @"\{\d+\}").Select(m => m.Value).Order()];
}
