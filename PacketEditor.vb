Option Strict On
Option Explicit On

Imports System

''' <summary>
''' Parsing degli header Ethernet/IPv4/TCP/UDP di un pacchetto grezzo e
''' applicazione delle regole di modifica (MAC/IP/porta di destinazione),
''' con ricalcolo dei checksum IP/TCP/UDP quando necessario.
''' Supporta solo link-layer Ethernet (DLT_EN10MB, network=1 nell'header
''' globale del pcap) e livello di rete IPv4: è la combinazione che si trova
''' nella stragrande maggioranza delle sniffate di rete via Wireshark.
''' </summary>
Public NotInheritable Class PacketEditor

    Private Const DLT_ETHERNET As UInteger = 1
    Private Const ETHERTYPE_VLAN As UShort = &H8100US
    Private Const ETHERTYPE_IPV4 As UShort = &H800US
    Private Const PROTO_TCP As Byte = 6
    Private Const PROTO_UDP As Byte = 17

    Private Sub New()
    End Sub

    Public Shared Function ParseHeaders(data As Byte(), linkType As UInteger) As PacketHeaderInfo
        Dim info As New PacketHeaderInfo()
        If linkType <> DLT_ETHERNET Then Return info
        If data.Length < 14 Then Return info

        info.HasEthernet = True
        info.DstMac = CopyRange(data, 0, 6)
        info.SrcMac = CopyRange(data, 6, 6)

        Dim etherTypeOffset As Integer = 12
        Dim etherType As UShort = ReadU16(data, etherTypeOffset)
        Dim ipOffset As Integer = 14
        If etherType = ETHERTYPE_VLAN Then
            If data.Length < 18 Then Return info
            etherType = ReadU16(data, 16)
            ipOffset = 18
        End If
        info.EtherType = etherType

        If etherType <> ETHERTYPE_IPV4 Then Return info
        If data.Length < ipOffset + 20 Then Return info

        Dim verIhl As Byte = data(ipOffset)
        Dim version As Integer = (verIhl >> 4) And &HF
        Dim ihl As Integer = (verIhl And &HF) * 4
        If version <> 4 OrElse ihl < 20 OrElse data.Length < ipOffset + ihl Then Return info

        info.HasIPv4 = True
        info.IpOffset = ipOffset
        info.IpHeaderLength = ihl
        info.Protocol = data(ipOffset + 9)
        info.SrcIp = CopyRange(data, ipOffset + 12, 4)
        info.DstIp = CopyRange(data, ipOffset + 16, 4)

        Dim transportOffset As Integer = ipOffset + ihl
        If info.Protocol = PROTO_TCP AndAlso data.Length >= transportOffset + 20 Then
            info.HasTransport = True
            info.TransportOffset = transportOffset
            info.SrcPort = ReadU16(data, transportOffset)
            info.DstPort = ReadU16(data, transportOffset + 2)
        ElseIf info.Protocol = PROTO_UDP AndAlso data.Length >= transportOffset + 8 Then
            info.HasTransport = True
            info.TransportOffset = transportOffset
            info.SrcPort = ReadU16(data, transportOffset)
            info.DstPort = ReadU16(data, transportOffset + 2)
        End If

        Return info
    End Function

    ''' <summary>
    ''' Applica le regole abilitate in <paramref name="rules"/> a una copia del
    ''' pacchetto originale, ricalcolando i checksum IP/TCP/UDP quando l'IP o
    ''' la porta di destinazione cambiano. Ritorna Nothing se il pacchetto non
    ''' ha un header Ethernet riconosciuto oppure se nessuna regola è applicabile.
    ''' </summary>
    Public Shared Function ApplyEdits(original As Byte(), info As PacketHeaderInfo, rules As EditRules) As Byte()
        If Not info.HasEthernet Then Return Nothing

        Dim wantsDstMac As Boolean = rules.EnableDstMac AndAlso rules.NewDstMacBytes IsNot Nothing AndAlso
            (rules.OriginalDstMacBytes Is Nothing OrElse BytesEqual(info.DstMac, rules.OriginalDstMacBytes))

        Dim wantsSrcMac As Boolean = rules.EnableSrcMac AndAlso rules.NewSrcMacBytes IsNot Nothing AndAlso
            (rules.OriginalSrcMacBytes Is Nothing OrElse BytesEqual(info.SrcMac, rules.OriginalSrcMacBytes))

        Dim wantsDstIp As Boolean = rules.EnableDstIp AndAlso info.HasIPv4 AndAlso rules.NewDstIpBytes IsNot Nothing AndAlso
            (rules.OriginalDstIpBytes Is Nothing OrElse BytesEqual(info.DstIp, rules.OriginalDstIpBytes))

        Dim wantsSrcIp As Boolean = rules.EnableSrcIp AndAlso info.HasIPv4 AndAlso rules.NewSrcIpBytes IsNot Nothing AndAlso
            (rules.OriginalSrcIpBytes Is Nothing OrElse BytesEqual(info.SrcIp, rules.OriginalSrcIpBytes))

        Dim wantsDstUdpPort As Boolean = rules.EnableDstUdpPort AndAlso info.HasTransport AndAlso info.Protocol = PROTO_UDP AndAlso
            (Not rules.OriginalDstUdpPort.HasValue OrElse info.DstPort = rules.OriginalDstUdpPort.Value)

        Dim wantsSrcUdpPort As Boolean = rules.EnableSrcUdpPort AndAlso info.HasTransport AndAlso info.Protocol = PROTO_UDP AndAlso
            (Not rules.OriginalSrcUdpPort.HasValue OrElse info.SrcPort = rules.OriginalSrcUdpPort.Value)

        Dim wantsDstTcpPort As Boolean = rules.EnableDstTcpPort AndAlso info.HasTransport AndAlso info.Protocol = PROTO_TCP AndAlso
            (Not rules.OriginalDstTcpPort.HasValue OrElse info.DstPort = rules.OriginalDstTcpPort.Value)

        Dim wantsSrcTcpPort As Boolean = rules.EnableSrcTcpPort AndAlso info.HasTransport AndAlso info.Protocol = PROTO_TCP AndAlso
            (Not rules.OriginalSrcTcpPort.HasValue OrElse info.SrcPort = rules.OriginalSrcTcpPort.Value)

        If Not (wantsDstMac OrElse wantsSrcMac OrElse wantsDstIp OrElse wantsSrcIp OrElse
                wantsDstUdpPort OrElse wantsSrcUdpPort OrElse wantsDstTcpPort OrElse wantsSrcTcpPort) Then
            Return Nothing
        End If

        Dim data As Byte() = CType(original.Clone(), Byte())
        Dim changedIp As Boolean = False
        Dim changedPort As Boolean = False

        If wantsDstMac Then Array.Copy(rules.NewDstMacBytes, 0, data, 0, 6)
        If wantsSrcMac Then Array.Copy(rules.NewSrcMacBytes, 0, data, 6, 6)

        If wantsDstIp Then
            Array.Copy(rules.NewDstIpBytes, 0, data, info.IpOffset + 16, 4)
            changedIp = True
        End If
        If wantsSrcIp Then
            Array.Copy(rules.NewSrcIpBytes, 0, data, info.IpOffset + 12, 4)
            changedIp = True
        End If

        If wantsDstUdpPort Then
            WriteU16(data, info.TransportOffset + 2, rules.NewDstUdpPort)
            changedPort = True
        ElseIf wantsDstTcpPort Then
            WriteU16(data, info.TransportOffset + 2, rules.NewDstTcpPort)
            changedPort = True
        End If

        If wantsSrcUdpPort Then
            WriteU16(data, info.TransportOffset + 0, rules.NewSrcUdpPort)
            changedPort = True
        ElseIf wantsSrcTcpPort Then
            WriteU16(data, info.TransportOffset + 0, rules.NewSrcTcpPort)
            changedPort = True
        End If

        If changedIp Then
            RecomputeIpChecksum(data, info.IpOffset, info.IpHeaderLength)
        End If

        If (changedIp OrElse changedPort) AndAlso info.HasTransport Then
            Dim transportLength As Integer = data.Length - info.TransportOffset
            If info.Protocol = PROTO_UDP Then
                RecomputeUdpChecksum(data, info.IpOffset, info.TransportOffset, transportLength)
            ElseIf info.Protocol = PROTO_TCP Then
                RecomputeTcpChecksum(data, info.IpOffset, info.TransportOffset, transportLength)
            End If
        End If

        Return data
    End Function

    Private Shared Function CopyRange(data As Byte(), offset As Integer, length As Integer) As Byte()
        Dim result(length - 1) As Byte
        Array.Copy(data, offset, result, 0, length)
        Return result
    End Function

    Private Shared Function BytesEqual(a As Byte(), b As Byte()) As Boolean
        If a Is Nothing OrElse b Is Nothing Then Return False
        If a.Length <> b.Length Then Return False
        For i As Integer = 0 To a.Length - 1
            If a(i) <> b(i) Then Return False
        Next
        Return True
    End Function

    Private Shared Function ReadU16(data As Byte(), offset As Integer) As UShort
        Return CType((CInt(data(offset)) << 8) Or data(offset + 1), UShort)
    End Function

    Private Shared Sub WriteU16(data As Byte(), offset As Integer, value As UShort)
        data(offset) = CByte((value >> 8) And &HFF)
        data(offset + 1) = CByte(value And &HFF)
    End Sub

    Private Shared Function FoldChecksum(sum As UInteger) As UShort
        While (sum >> 16) <> 0
            sum = (sum And &HFFFFUI) + (sum >> 16)
        End While
        Return CType(Not CUShort(sum And &HFFFFUI), UShort)
    End Function

    Private Shared Sub RecomputeIpChecksum(data As Byte(), ipOffset As Integer, ipHeaderLength As Integer)
        data(ipOffset + 10) = 0
        data(ipOffset + 11) = 0
        Dim sum As UInteger = SumRange(data, ipOffset, ipHeaderLength)
        WriteU16(data, ipOffset + 10, FoldChecksum(sum))
    End Sub

    Private Shared Sub RecomputeUdpChecksum(data As Byte(), ipOffset As Integer, udpOffset As Integer, udpLength As Integer)
        data(udpOffset + 6) = 0
        data(udpOffset + 7) = 0
        Dim sum As UInteger = PseudoHeaderSum(data, ipOffset, PROTO_UDP, udpLength)
        sum += SumRange(data, udpOffset, udpLength)
        Dim checksum As UShort = FoldChecksum(sum)
        If checksum = 0 Then checksum = &HFFFF ' RFC 768: 0 significa "checksum non calcolato"
        WriteU16(data, udpOffset + 6, checksum)
    End Sub

    Private Shared Sub RecomputeTcpChecksum(data As Byte(), ipOffset As Integer, tcpOffset As Integer, tcpLength As Integer)
        data(tcpOffset + 16) = 0
        data(tcpOffset + 17) = 0
        Dim sum As UInteger = PseudoHeaderSum(data, ipOffset, PROTO_TCP, tcpLength)
        sum += SumRange(data, tcpOffset, tcpLength)
        WriteU16(data, tcpOffset + 16, FoldChecksum(sum))
    End Sub

    Private Shared Function PseudoHeaderSum(data As Byte(), ipOffset As Integer, protocol As Byte, length As Integer) As UInteger
        Dim sum As UInteger = 0
        sum += ReadU16(data, ipOffset + 12)
        sum += ReadU16(data, ipOffset + 14)
        sum += ReadU16(data, ipOffset + 16)
        sum += ReadU16(data, ipOffset + 18)
        sum += CUInt(protocol)
        sum += CUInt(length)
        Return sum
    End Function

    Private Shared Function SumRange(data As Byte(), offset As Integer, length As Integer) As UInteger
        Dim sum As UInteger = 0
        Dim i As Integer = offset
        Dim endOffset As Integer = offset + length
        While i + 1 < endOffset
            sum += ReadU16(data, i)
            i += 2
        End While
        If i < endOffset Then
            sum += CUInt(CInt(data(i)) << 8)
        End If
        Return sum
    End Function

End Class
