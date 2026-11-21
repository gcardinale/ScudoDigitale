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

using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;

using ScudoDigitale.Core.Dns;

namespace ScudoDigitale.Core.Tests;

/// <summary>
/// A minimal authoritative-looking DNS server on UDP loopback, so <see cref="DnsClientResolver"/>
/// is tested on real DNS packets without touching the network. It answers TXT, MX, A, AAAA and
/// follows one CNAME; selected names can answer NXDOMAIN, SERVFAIL or nothing at all.
/// </summary>
internal sealed class FakeDnsServer : IAsyncDisposable
{
    public const ushort A = 1;
    public const ushort Cname = 5;
    public const ushort Mx = 15;
    public const ushort Txt = 16;
    public const ushort Aaaa = 28;

    private readonly UdpClient udp = new(new IPEndPoint(IPAddress.Loopback, 0));
    private readonly CancellationTokenSource stop = new();
    private readonly Dictionary<(string Name, ushort Type), List<byte[]>> records = [];
    private readonly Task loop;

    public FakeDnsServer()
    {
        loop = Task.Run(RunAsync);
    }

    public int Port => ((IPEndPoint)udp.Client.LocalEndPoint!).Port;

    public HashSet<string> NonExistent { get; } = new(StringComparer.OrdinalIgnoreCase);

    public HashSet<string> ServerFailure { get; } = new(StringComparer.OrdinalIgnoreCase);

    public HashSet<string> Silent { get; } = new(StringComparer.OrdinalIgnoreCase);

    public int Received { get; private set; }

    public FakeDnsServer AddTxt(string name, params string[] strings)
    {
        var data = new List<byte>();
        foreach (var s in strings)
        {
            var bytes = Encoding.ASCII.GetBytes(s);
            data.Add((byte)bytes.Length);
            data.AddRange(bytes);
        }

        return Add(name, Txt, [.. data]);
    }

    public FakeDnsServer AddMx(string name, ushort preference, string host)
    {
        var data = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(data, preference);
        return Add(name, Mx, [.. data, .. EncodeName(host)]);
    }

    public FakeDnsServer AddAddress(string name, string address)
    {
        var ip = IPAddress.Parse(address);
        return Add(name, ip.AddressFamily == AddressFamily.InterNetwork ? A : Aaaa, ip.GetAddressBytes());
    }

    public FakeDnsServer AddCname(string name, string target) => Add(name, Cname, EncodeName(target));

    public async ValueTask DisposeAsync()
    {
        await stop.CancelAsync();
        try
        {
            await loop;
        }
        catch (OperationCanceledException)
        {
        }

        udp.Dispose();
        stop.Dispose();
    }

    private FakeDnsServer Add(string name, ushort type, byte[] data)
    {
        var key = (name.ToLowerInvariant(), type);
        if (!records.TryGetValue(key, out var list))
        {
            records[key] = list = [];
        }

        list.Add(data);
        return this;
    }

    private async Task RunAsync()
    {
        while (!stop.IsCancellationRequested)
        {
            UdpReceiveResult received;
            try
            {
                received = await udp.ReceiveAsync(stop.Token);
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (SocketException)
            {
                // Windows reports an ICMP "port unreachable" of a previous reply as a receive error.
                continue;
            }

            Received++;
            var reply = Reply(received.Buffer);
            if (reply is not null)
            {
                await udp.SendAsync(reply, received.RemoteEndPoint, stop.Token);
            }
        }
    }

    private byte[]? Reply(byte[] request)
    {
        var offset = 12;
        var labels = new List<string>();
        while (request[offset] != 0)
        {
            var length = request[offset];
            labels.Add(Encoding.ASCII.GetString(request, offset + 1, length));
            offset += length + 1;
        }

        var questionEnd = offset + 1 + 4;
        var name = string.Join('.', labels).ToLowerInvariant();
        var type = BinaryPrimitives.ReadUInt16BigEndian(request.AsSpan(offset + 1));
        if (Silent.Contains(name))
        {
            return null;
        }

        var rcode = ServerFailure.Contains(name) ? 2 : NonExistent.Contains(name) ? 3 : 0;
        var answers = new List<(string Owner, ushort Type, byte[] Data)>();
        if (rcode == 0)
        {
            var owner = name;
            if (records.TryGetValue((name, Cname), out var cname) && type != Cname)
            {
                answers.Add((name, Cname, cname[0]));
                owner = DecodeName(cname[0]);
            }

            if (records.TryGetValue((owner, type), out var found))
            {
                answers.AddRange(found.Select(data => (owner, type, data)));
            }
        }

        var response = new List<byte>();
        response.AddRange(request.AsSpan(0, 2).ToArray());
        response.AddRange([0x81, (byte)(0x80 | rcode)]);
        response.AddRange([0, 1]);
        response.AddRange(UInt16(answers.Count));
        response.AddRange([0, 0, 0, 0]);
        response.AddRange(request.AsSpan(12, questionEnd - 12).ToArray());
        foreach (var (owner, answerType, data) in answers)
        {
            response.AddRange(EncodeName(owner));
            response.AddRange(UInt16(answerType));
            response.AddRange([0, 1]);
            response.AddRange([0, 0, 1, 44]);
            response.AddRange(UInt16(data.Length));
            response.AddRange(data);
        }

        return [.. response];
    }

    private static byte[] UInt16(int value) => [(byte)(value >> 8), (byte)value];

    private static byte[] EncodeName(string name)
    {
        var bytes = new List<byte>();
        foreach (var label in name.TrimEnd('.').Split('.', StringSplitOptions.RemoveEmptyEntries))
        {
            bytes.Add((byte)label.Length);
            bytes.AddRange(Encoding.ASCII.GetBytes(label));
        }

        bytes.Add(0);
        return [.. bytes];
    }

    private static string DecodeName(byte[] data)
    {
        var labels = new List<string>();
        var offset = 0;
        while (data[offset] != 0)
        {
            labels.Add(Encoding.ASCII.GetString(data, offset + 1, data[offset]));
            offset += data[offset] + 1;
        }

        return string.Join('.', labels).ToLowerInvariant();
    }
}
