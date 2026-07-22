using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using BacchackSniffChangeReplay;

int failures = 0;

void Check(bool condition, string description)
{
    if (condition)
    {
        Console.WriteLine($"  OK   {description}");
    }
    else
    {
        Console.WriteLine($"  FAIL {description}");
        failures++;
    }
}

byte[] Mac(string s) => s.Split(':').Select(h => Convert.ToByte(h, 16)).ToArray();
byte[] Ip(string s) => IPAddress.Parse(s).GetAddressBytes();

byte[] BuildUdpPacket(byte[] dstMac, byte[] srcMac, byte[] srcIp, byte[] dstIp, ushort srcPort, ushort dstPort, byte[] payload)
{
    int udpLen = 8 + payload.Length;
    int totalLen = 20 + udpLen;
    var ip = new byte[20];
    ip[0] = 0x45; ip[1] = 0x00;
    ip[2] = (byte)(totalLen >> 8); ip[3] = (byte)(totalLen & 0xFF);
    ip[6] = 0x40;
    ip[8] = 64;
    ip[9] = 17;
    Array.Copy(srcIp, 0, ip, 12, 4);
    Array.Copy(dstIp, 0, ip, 16, 4);

    var udp = new byte[udpLen];
    udp[0] = (byte)(srcPort >> 8); udp[1] = (byte)(srcPort & 0xFF);
    udp[2] = (byte)(dstPort >> 8); udp[3] = (byte)(dstPort & 0xFF);
    udp[4] = (byte)(udpLen >> 8); udp[5] = (byte)(udpLen & 0xFF);
    Array.Copy(payload, 0, udp, 8, payload.Length);

    var eth = new byte[14];
    Array.Copy(dstMac, 0, eth, 0, 6);
    Array.Copy(srcMac, 0, eth, 6, 6);
    eth[12] = 0x08; eth[13] = 0x00;

    return eth.Concat(ip).Concat(udp).ToArray();
}

byte[] BuildTcpPacket(byte[] dstMac, byte[] srcMac, byte[] srcIp, byte[] dstIp, ushort srcPort, ushort dstPort, byte[] payload)
{
    int tcpLen = 20 + payload.Length;
    int totalLen = 20 + tcpLen;
    var ip = new byte[20];
    ip[0] = 0x45; ip[1] = 0x00;
    ip[2] = (byte)(totalLen >> 8); ip[3] = (byte)(totalLen & 0xFF);
    ip[6] = 0x40;
    ip[8] = 64;
    ip[9] = 6;
    Array.Copy(srcIp, 0, ip, 12, 4);
    Array.Copy(dstIp, 0, ip, 16, 4);

    var tcp = new byte[tcpLen];
    tcp[0] = (byte)(srcPort >> 8); tcp[1] = (byte)(srcPort & 0xFF);
    tcp[2] = (byte)(dstPort >> 8); tcp[3] = (byte)(dstPort & 0xFF);
    tcp[12] = 0x50; // data offset = 5 words
    tcp[13] = 0x02; // flags: SYN
    tcp[14] = 0xFF; tcp[15] = 0xFF; // window
    Array.Copy(payload, 0, tcp, 20, payload.Length);

    var eth = new byte[14];
    Array.Copy(dstMac, 0, eth, 0, 6);
    Array.Copy(srcMac, 0, eth, 6, 6);
    eth[12] = 0x08; eth[13] = 0x00;

    return eth.Concat(ip).Concat(tcp).ToArray();
}

void WritePcapFile(string path, List<(DateTime ts, byte[] data)> packets)
{
    using var fs = new FileStream(path, FileMode.Create, FileAccess.Write);
    using var bw = new BinaryWriter(fs);
    bw.Write((uint)0xa1b2c3d4);
    bw.Write((ushort)2);
    bw.Write((ushort)4);
    bw.Write(0);
    bw.Write((uint)0);
    bw.Write((uint)65535);
    bw.Write((uint)1); // LINKTYPE_ETHERNET

    var epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
    foreach (var (ts, data) in packets)
    {
        var delta = ts - epoch;
        uint tsSec = (uint)Math.Floor(delta.TotalSeconds);
        uint tsUsec = (uint)((delta.TotalMilliseconds - tsSec * 1000.0) * 1000.0);
        bw.Write(tsSec);
        bw.Write(tsUsec);
        bw.Write((uint)data.Length);
        bw.Write((uint)data.Length);
        bw.Write(data);
    }
}

ushort SumFold(IEnumerable<byte> bytes)
{
    var arr = bytes.ToArray();
    uint sum = 0;
    for (int i = 0; i < arr.Length; i += 2)
    {
        ushort word = (ushort)(arr[i] << 8);
        if (i + 1 < arr.Length) word |= arr[i + 1];
        sum += word;
    }
    while ((sum >> 16) != 0) sum = (sum & 0xFFFF) + (sum >> 16);
    return (ushort)sum;
}

bool VerifyIpChecksum(byte[] data, PacketHeaderInfo info)
{
    var header = data.Skip(info.IpOffset).Take(info.IpHeaderLength);
    return SumFold(header) == 0xFFFF;
}

bool VerifyTransportChecksum(byte[] data, PacketHeaderInfo info, byte protocol)
{
    int transportLen = data.Length - info.TransportOffset;
    var pseudo = new List<byte>();
    pseudo.AddRange(data.Skip(info.IpOffset + 12).Take(4));
    pseudo.AddRange(data.Skip(info.IpOffset + 16).Take(4));
    pseudo.Add(0);
    pseudo.Add(protocol);
    pseudo.Add((byte)(transportLen >> 8));
    pseudo.Add((byte)(transportLen & 0xFF));
    pseudo.AddRange(data.Skip(info.TransportOffset).Take(transportLen));
    return SumFold(pseudo) == 0xFFFF;
}

// -------------------------------------------------------------------------
// Test 1: costruzione di un file pcap sintetico e lettura con PcapFileReader
// -------------------------------------------------------------------------

Console.WriteLine("=== Test 1: costruzione e lettura di un file pcap sintetico ===");

var t0 = new DateTime(2026, 1, 1, 12, 0, 0, DateTimeKind.Utc);

var udpPacket = BuildUdpPacket(
    dstMac: Mac("AA:AA:AA:AA:AA:AA"), srcMac: Mac("00:11:22:33:44:55"),
    srcIp: Ip("10.0.0.5"), dstIp: Ip("10.0.0.9"),
    srcPort: 12345, dstPort: 5000,
    payload: Encoding.ASCII.GetBytes("PING-TEST"));

var tcpPacket = BuildTcpPacket(
    dstMac: Mac("BB:BB:BB:BB:BB:BB"), srcMac: Mac("00:11:22:33:44:66"),
    srcIp: Ip("10.0.0.6"), dstIp: Ip("10.0.0.10"),
    srcPort: 33445, dstPort: 8080,
    payload: Encoding.ASCII.GetBytes("SYN-TEST-PAYLOAD-DATA"));

var pcapPath = Path.Combine(Path.GetTempPath(), "bacchack_test.pcap");
WritePcapFile(pcapPath, new List<(DateTime, byte[])>
{
    (t0, udpPacket),
    (t0.AddMilliseconds(250), tcpPacket),
});

uint linkType = 0;
var packets = PcapFileReader.ReadFile(pcapPath, ref linkType);

Check(packets.Count == 2, $"letti 2 pacchetti (trovati {packets.Count})");
Check(linkType == 1, $"linktype Ethernet (=1), trovato {linkType}");

var p0 = packets[0];
var p1 = packets[1];

Check(p0.Info.HasEthernet && p0.Info.HasIPv4 && p0.Info.HasTransport, "pacchetto 0: header Ethernet/IPv4/transport riconosciuti");
Check(p0.Info.ProtocolName() == "UDP", $"pacchetto 0 riconosciuto come UDP (trovato {p0.Info.ProtocolName()})");
Check(BitConverter.ToString(p0.Info.DstMac) == "AA-AA-AA-AA-AA-AA", "pacchetto 0: MAC destinazione originale corretto");
Check(new IPAddress(p0.Info.DstIp).ToString() == "10.0.0.9", "pacchetto 0: IP destinazione originale corretto");
Check(p0.Info.DstPort == 5000, "pacchetto 0: porta UDP destinazione originale corretta");

Check(p1.Info.ProtocolName() == "TCP", $"pacchetto 1 riconosciuto come TCP (trovato {p1.Info.ProtocolName()})");
Check(p1.Info.DstPort == 8080, "pacchetto 1: porta TCP destinazione originale corretta");

var deltaMs = (p1.Timestamp - p0.Timestamp).TotalMilliseconds;
Check(Math.Abs(deltaMs - 250.0) < 1.0, $"delta timestamp tra i due pacchetti ~250ms (trovato {deltaMs:F1}ms)");

Console.WriteLine();
Console.WriteLine("=== Test 2: applicazione delle regole di modifica + ricalcolo checksum ===");

// 2a: regole "jolly" (valore originale vuoto = si applica a qualsiasi pacchetto),
// stesso comportamento del vecchio editor globale.
var wildcardRules = new EditRules
{
    EnableDstMac = true,
    NewDstMacText = "12:34:56:78:9A:BC",
    EnableDstIp = true,
    NewDstIpText = "192.168.50.77",
    EnableDstUdpPort = true,
    NewDstUdpPort = 6000,
    EnableDstTcpPort = true,
    NewDstTcpPort = 9090,
};

string err = "";
bool rulesValid = wildcardRules.Validate(ref err);
Check(rulesValid, $"regole jolly valide (errore: '{err}')");

var editedUdp = PacketEditor.ApplyEdits(p0.OriginalBytes, p0.Info, wildcardRules);
Check(editedUdp != null, "jolly: pacchetto UDP modificato (ApplyEdits non torna null)");
if (editedUdp != null)
{
    var info = PacketEditor.ParseHeaders(editedUdp, linkType);
    Check(BitConverter.ToString(info.DstMac) == "12-34-56-78-9A-BC", "jolly UDP: MAC destinazione aggiornato");
    Check(new IPAddress(info.DstIp).ToString() == "192.168.50.77", "jolly UDP: IP destinazione aggiornato");
    Check(info.DstPort == 6000, "jolly UDP: porta destinazione aggiornata");
    Check(VerifyIpChecksum(editedUdp, info), "jolly UDP: checksum header IP valido dopo la modifica");
    Check(VerifyTransportChecksum(editedUdp, info, 17), "jolly UDP: checksum UDP valido dopo la modifica");
}

var editedTcp = PacketEditor.ApplyEdits(p1.OriginalBytes, p1.Info, wildcardRules);
Check(editedTcp != null, "jolly: pacchetto TCP modificato (ApplyEdits non torna null)");
if (editedTcp != null)
{
    var info = PacketEditor.ParseHeaders(editedTcp, linkType);
    Check(BitConverter.ToString(info.DstMac) == "12-34-56-78-9A-BC", "jolly TCP: MAC destinazione aggiornato");
    Check(new IPAddress(info.DstIp).ToString() == "192.168.50.77", "jolly TCP: IP destinazione aggiornato");
    Check(info.DstPort == 9090, "jolly TCP: porta destinazione aggiornata");
    Check(VerifyIpChecksum(editedTcp, info), "jolly TCP: checksum header IP valido dopo la modifica");
    Check(VerifyTransportChecksum(editedTcp, info, 6), "jolly TCP: checksum TCP valido dopo la modifica");
}

// Nessuna regola abilitata -> nessuna modifica
var noRules = new EditRules();
var untouched = PacketEditor.ApplyEdits(p0.OriginalBytes, p0.Info, noRules);
Check(untouched == null, "senza regole abilitate, ApplyEdits non tocca il pacchetto (torna null)");

// 2b: regola selettiva sull'IP (originale = 10.0.0.9, quello di p0) -> deve toccare
// solo p0 e lasciare p1 (dst originale 10.0.0.10) invariato.
var selectiveIpRules = new EditRules
{
    EnableDstIp = true,
    OriginalDstIpText = "10.0.0.9",
    NewDstIpText = "192.168.99.99",
};
Check(selectiveIpRules.Validate(ref err), $"regola selettiva IP valida (errore: '{err}')");

var p0MatchIp = PacketEditor.ApplyEdits(p0.OriginalBytes, p0.Info, selectiveIpRules);
Check(p0MatchIp != null, "selettiva IP: p0 (dst originale corrispondente) viene modificato");
if (p0MatchIp != null)
{
    var info = PacketEditor.ParseHeaders(p0MatchIp, linkType);
    Check(new IPAddress(info.DstIp).ToString() == "192.168.99.99", "selettiva IP: p0 ha il nuovo IP di destinazione");
}

var p1NoMatchIp = PacketEditor.ApplyEdits(p1.OriginalBytes, p1.Info, selectiveIpRules);
Check(p1NoMatchIp == null, "selettiva IP: p1 (dst originale diverso) resta invariato (ApplyEdits torna null)");

// 2c: regola selettiva sulla porta UDP con valore originale che NON corrisponde
// (p0 ha porta UDP dest. 5000, filtro cerca 9999) -> nessuna modifica.
var portMismatchRules = new EditRules
{
    EnableDstUdpPort = true,
    OriginalDstUdpPortText = "9999",
    NewDstUdpPort = 7000,
};
Check(portMismatchRules.Validate(ref err), $"regola porta (mismatch) valida (errore: '{err}')");
var p0PortMismatch = PacketEditor.ApplyEdits(p0.OriginalBytes, p0.Info, portMismatchRules);
Check(p0PortMismatch == null, "selettiva porta UDP: filtro non corrispondente -> nessuna modifica");

// 2d: stessa regola ma con il valore originale corretto (5000) -> deve modificare.
var portMatchRules = new EditRules
{
    EnableDstUdpPort = true,
    OriginalDstUdpPortText = "5000",
    NewDstUdpPort = 7000,
};
Check(portMatchRules.Validate(ref err), $"regola porta (match) valida (errore: '{err}')");
var p0PortMatch = PacketEditor.ApplyEdits(p0.OriginalBytes, p0.Info, portMatchRules);
Check(p0PortMatch != null, "selettiva porta UDP: filtro corrispondente -> pacchetto modificato");
if (p0PortMatch != null)
{
    var info = PacketEditor.ParseHeaders(p0PortMatch, linkType);
    Check(info.DstPort == 7000, "selettiva porta UDP: nuova porta applicata correttamente");
}

// 2e: campi MITTENTE (MAC/IP/porta UDP). p0 ha MAC sorgente 00:11:22:33:44:55,
// IP sorgente 10.0.0.5, porta UDP sorgente 12345.
var srcMacRules = new EditRules
{
    EnableSrcMac = true,
    NewSrcMacText = "AA:BB:CC:11:22:33",
};
Check(srcMacRules.Validate(ref err), $"regola MAC mittente valida (errore: '{err}')");
var p0SrcMac = PacketEditor.ApplyEdits(p0.OriginalBytes, p0.Info, srcMacRules);
Check(p0SrcMac != null, "MAC mittente: pacchetto modificato");
if (p0SrcMac != null)
{
    var info = PacketEditor.ParseHeaders(p0SrcMac, linkType);
    Check(BitConverter.ToString(info.SrcMac) == "AA-BB-CC-11-22-33", "MAC mittente: nuovo MAC applicato");
    Check(BitConverter.ToString(info.DstMac) == "AA-AA-AA-AA-AA-AA", "MAC mittente: MAC destinazione non toccato");
}

var srcIpMatchRules = new EditRules
{
    EnableSrcIp = true,
    OriginalSrcIpText = "10.0.0.5",
    NewSrcIpText = "172.16.0.99",
};
Check(srcIpMatchRules.Validate(ref err), $"regola IP mittente (match) valida (errore: '{err}')");
var p0SrcIpMatch = PacketEditor.ApplyEdits(p0.OriginalBytes, p0.Info, srcIpMatchRules);
Check(p0SrcIpMatch != null, "IP mittente: filtro corrispondente -> pacchetto modificato");
if (p0SrcIpMatch != null)
{
    var info = PacketEditor.ParseHeaders(p0SrcIpMatch, linkType);
    Check(new IPAddress(info.SrcIp).ToString() == "172.16.0.99", "IP mittente: nuovo IP applicato");
    Check(new IPAddress(info.DstIp).ToString() == "10.0.0.9", "IP mittente: IP destinazione non toccato");
    Check(VerifyIpChecksum(p0SrcIpMatch, info), "IP mittente: checksum IP valido dopo la modifica");
    Check(VerifyTransportChecksum(p0SrcIpMatch, info, 17), "IP mittente: checksum UDP valido dopo la modifica");
}

var srcIpMismatchRules = new EditRules
{
    EnableSrcIp = true,
    OriginalSrcIpText = "9.9.9.9",
    NewSrcIpText = "172.16.0.99",
};
Check(srcIpMismatchRules.Validate(ref err), $"regola IP mittente (mismatch) valida (errore: '{err}')");
var p0SrcIpMismatch = PacketEditor.ApplyEdits(p0.OriginalBytes, p0.Info, srcIpMismatchRules);
Check(p0SrcIpMismatch == null, "IP mittente: filtro non corrispondente -> nessuna modifica");

var srcPortRules = new EditRules
{
    EnableSrcUdpPort = true,
    OriginalSrcUdpPortText = "12345",
    NewSrcUdpPort = 55555,
};
Check(srcPortRules.Validate(ref err), $"regola porta UDP mittente valida (errore: '{err}')");
var p0SrcPort = PacketEditor.ApplyEdits(p0.OriginalBytes, p0.Info, srcPortRules);
Check(p0SrcPort != null, "porta UDP mittente: pacchetto modificato");
if (p0SrcPort != null)
{
    var info = PacketEditor.ParseHeaders(p0SrcPort, linkType);
    Check(info.SrcPort == 55555, "porta UDP mittente: nuova porta applicata");
    Check(info.DstPort == 5000, "porta UDP mittente: porta destinazione non toccata");
    Check(VerifyTransportChecksum(p0SrcPort, info, 17), "porta UDP mittente: checksum UDP valido dopo la modifica");
}

Console.WriteLine();
Console.WriteLine("=== Test 3: enumerazione interfacce di rete (Npcap) ===");
try
{
    var devices = WinPcap.ListDevices();
    Check(devices.Count > 0, $"trovate {devices.Count} interfacce di rete");
    foreach (var d in devices) Console.WriteLine($"    - {d}");
}
catch (Exception ex)
{
    Console.WriteLine($"  FAIL enumerazione interfacce: {ex.Message}");
    failures++;
}

Console.WriteLine();
Console.WriteLine("=== Test 4: invio multiplo reale su adattatore di loopback Npcap ===");
try
{
    var loopbackDevice = WinPcap.ListDevices().FirstOrDefault(d => d.Name.IndexOf("loopback", StringComparison.OrdinalIgnoreCase) >= 0);
    if (loopbackDevice == null)
    {
        Console.WriteLine("  SKIP nessun adattatore di loopback trovato");
    }
    else
    {
        using var sender = WinPcap.OpenLive(loopbackDevice.Name);
        int sent = 0;
        for (int i = 0; i < 20; i++)
        {
            var frame = BuildUdpPacket(
                dstMac: Mac("FF:FF:FF:FF:FF:FF"), srcMac: Mac("00:00:00:00:00:01"),
                srcIp: Ip("127.0.0.1"), dstIp: Ip("127.0.0.1"),
                srcPort: 40000, dstPort: (ushort)(50000 + i),
                payload: Encoding.ASCII.GetBytes("LOOPBACK-TEST-" + i));
            sender.Send(frame);
            sent++;
        }
        Check(sent == 20, $"inviati 20/20 pacchetti consecutivi su '{loopbackDevice}' senza errori");
    }
}
catch (Exception ex)
{
    Console.WriteLine($"  FAIL invio multiplo su loopback: {ex.Message}");
    failures++;
}

Console.WriteLine();
File.Delete(pcapPath);

if (failures == 0)
{
    Console.WriteLine("TUTTI I TEST SUPERATI.");
    return 0;
}

Console.WriteLine($"{failures} TEST FALLITI.");
return 1;
