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

using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace ScudoDigitale.Checks.Web;

/// <summary>Reads what the checks need from the certificate and the chain of a TLS handshake.</summary>
internal static class CertificateInspector
{
    /// <summary>Describes the certificate a host presented.</summary>
    /// <param name="host">The host that was contacted.</param>
    /// <param name="certificate">Its certificate.</param>
    /// <param name="chain">The chain built during the handshake.</param>
    /// <param name="errors">The errors found during the handshake.</param>
    /// <returns>The description.</returns>
    public static CertificateInfo Describe(string host, X509Certificate2 certificate, X509Chain chain, SslPolicyErrors errors)
    {
        var flags = chain.ChainStatus.Aggregate(X509ChainStatusFlags.NoError, (all, status) => all | status.Status);

        // An expired certificate is the subject of its own check; here only the rest of the chain counts.
        var issuersAreInDate = chain.ChainElements.Skip(1)
            .All(element => element.ChainElementStatus.All(status => status.Status != X509ChainStatusFlags.NotTimeValid));
        if (issuersAreInDate)
        {
            flags &= ~X509ChainStatusFlags.NotTimeValid;
        }

        return new CertificateInfo(
            host,
            Names(certificate),
            certificate.NotBefore.ToUniversalTime(),
            certificate.NotAfter.ToUniversalTime(),
            (errors & SslPolicyErrors.RemoteCertificateNameMismatch) == 0,
            Classify(flags),
            flags.ToString());
    }

    /// <summary>Judges a chain from its status flags.</summary>
    /// <param name="flags">The flags of the whole chain.</param>
    /// <returns>Trusted with no flag, incomplete when only the issuer is missing, untrusted otherwise.</returns>
    internal static ChainState Classify(X509ChainStatusFlags flags) => flags switch
    {
        X509ChainStatusFlags.NoError => ChainState.Trusted,
        X509ChainStatusFlags.PartialChain => ChainState.Incomplete,
        _ => ChainState.Untrusted,
    };

    /// <summary>The DNS names of a certificate: its alternative names, or its common name when it has none.</summary>
    /// <param name="certificate">The certificate.</param>
    /// <returns>The names.</returns>
    internal static IReadOnlyList<string> Names(X509Certificate2 certificate)
    {
        var names = certificate.Extensions.OfType<X509SubjectAlternativeNameExtension>()
            .SelectMany(extension => extension.EnumerateDnsNames())
            .ToArray();
        return names.Length > 0 ? names : [certificate.GetNameInfo(X509NameType.SimpleName, forIssuer: false)];
    }
}
