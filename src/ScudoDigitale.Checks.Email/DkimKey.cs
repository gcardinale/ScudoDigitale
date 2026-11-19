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

using System.Formats.Asn1;

namespace ScudoDigitale.Checks.Email;

/// <summary>A DKIM key record published at <c>&lt;selector&gt;._domainkey.&lt;domain&gt;</c> (RFC 6376 §3.6.1).</summary>
/// <param name="Selector">The selector.</param>
/// <param name="KeyType">The <c>k</c> tag, <c>rsa</c> when absent.</param>
/// <param name="Bits">Length of the RSA modulus, when the key is an RSA key that could be read.</param>
/// <param name="Revoked">Whether the key is revoked (empty <c>p</c> tag).</param>
/// <param name="Readable">Whether the key could be decoded.</param>
/// <param name="Testing">Whether the <c>t</c> tag contains the flag <c>y</c> (test mode).</param>
internal sealed record DkimKey(string Selector, string KeyType, int? Bits, bool Revoked, bool Readable, bool Testing)
{
    private const string RsaOid = "1.2.840.113549.1.1.1";
    private const int Ed25519KeyLength = 32;

    /// <summary>
    /// Parses a TXT record as a DKIM key. A record without a <c>p</c> tag, or with a version other
    /// than <c>DKIM1</c>, is not a DKIM key (it can come from a wildcard TXT record).
    /// </summary>
    /// <param name="selector">The selector that was queried.</param>
    /// <param name="text">The TXT record.</param>
    /// <returns>The key, or <see langword="null"/> when the record is not a DKIM key.</returns>
    public static DkimKey? TryParse(string selector, string text)
    {
        var tags = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var part in text.Split(';'))
        {
            var equals = part.IndexOf('=', StringComparison.Ordinal);
            if (equals > 0)
            {
                tags.TryAdd(part[..equals].Trim().ToLowerInvariant(), part[(equals + 1)..]);
            }
        }

        if (!tags.TryGetValue("p", out var p) || (tags.TryGetValue("v", out var version) && version.Trim() != "DKIM1"))
        {
            return null;
        }

        var keyType = tags.TryGetValue("k", out var k) ? k.Trim().ToLowerInvariant() : "rsa";
        var testing = tags.TryGetValue("t", out var t) && t.Split(':').Any(flag => flag.Trim().Equals("y", StringComparison.OrdinalIgnoreCase));
        var base64 = string.Concat(p.Where(c => !char.IsWhiteSpace(c)));
        if (base64.Length == 0)
        {
            return new DkimKey(selector, keyType, null, Revoked: true, Readable: true, testing);
        }

        byte[] key;
        try
        {
            key = Convert.FromBase64String(base64);
        }
        catch (FormatException)
        {
            return new DkimKey(selector, keyType, null, Revoked: false, Readable: false, testing);
        }

        return keyType switch
        {
            "rsa" when RsaModulusBits(key) is { } bits => new DkimKey(selector, keyType, bits, false, true, testing),
            "ed25519" when key.Length == Ed25519KeyLength => new DkimKey(selector, keyType, null, false, true, testing),
            _ => new DkimKey(selector, keyType, null, false, false, testing),
        };
    }

    /// <summary>
    /// Length in bits of the modulus of an RSA public key, in SubjectPublicKeyInfo form (what DKIM
    /// publishes) or as a bare PKCS#1 RSAPublicKey (which some providers publish). Read from the DER
    /// structure, so it does not depend on the crypto library of the operating system.
    /// </summary>
    /// <param name="der">The decoded key.</param>
    /// <returns>The number of bits, or <see langword="null"/> when the bytes are not an RSA key.</returns>
    internal static int? RsaModulusBits(byte[] der)
    {
        try
        {
            var outer = new AsnReader(der, AsnEncodingRules.DER);
            var sequence = outer.ReadSequence();
            if (sequence.PeekTag().HasSameClassAndValue(Asn1Tag.Sequence))
            {
                var algorithm = sequence.ReadSequence();
                if (algorithm.ReadObjectIdentifier() != RsaOid)
                {
                    return null;
                }

                var publicKey = sequence.ReadBitString(out _);
                sequence = new AsnReader(publicKey, AsnEncodingRules.DER).ReadSequence();
            }

            var modulus = sequence.ReadIntegerBytes().Span.TrimStart((byte)0);
            return modulus.IsEmpty ? null : ((modulus.Length - 1) * 8) + (8 - byte.LeadingZeroCount(modulus[0]));
        }
        catch (AsnContentException)
        {
            return null;
        }
    }
}
