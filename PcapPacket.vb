Option Strict On
Option Explicit On

Imports System

''' <summary>
''' Informazioni sugli header Ethernet/IPv4/TCP/UDP estratte da un pacchetto,
''' usate sia per la visualizzazione in griglia sia per applicare le regole
''' di modifica prima del replay. Se un livello non è presente o non è
''' riconosciuto (es. IPv6, link-layer diverso da Ethernet), i relativi campi
''' "Has..." restano False e il resto della struttura va ignorato.
''' </summary>
Public Structure PacketHeaderInfo

    Public HasEthernet As Boolean
    Public DstMac As Byte()
    Public SrcMac As Byte()
    Public EtherType As UShort

    Public HasIPv4 As Boolean
    Public IpOffset As Integer
    Public IpHeaderLength As Integer
    Public Protocol As Byte
    Public SrcIp As Byte()
    Public DstIp As Byte()

    Public HasTransport As Boolean
    Public TransportOffset As Integer
    Public SrcPort As UShort
    Public DstPort As UShort

    Public Function ProtocolName() As String
        If Not HasIPv4 Then Return ""
        Select Case Protocol
            Case 6 : Return "TCP"
            Case 17 : Return "UDP"
            Case 1 : Return "ICMP"
            Case Else : Return "0x" & Protocol.ToString("X2")
        End Select
    End Function

End Structure

''' <summary>
''' Rappresenta un singolo pacchetto letto da un file pcap, con i byte
''' originali (immutabili) e un'eventuale versione modificata dalle regole
''' di editing, pronta per essere inviata durante il replay.
''' </summary>
Public NotInheritable Class PcapPacket

    Public ReadOnly Property Index As Integer
    Public ReadOnly Property Timestamp As DateTime
    Public ReadOnly Property OriginalBytes As Byte()
    Public ReadOnly Property OriginalLength As UInteger
    Public ReadOnly Property Info As PacketHeaderInfo

    Public Property EditedBytes As Byte()

    Public ReadOnly Property IsEdited As Boolean
        Get
            Return EditedBytes IsNot Nothing
        End Get
    End Property

    Public ReadOnly Property BytesToSend As Byte()
        Get
            If EditedBytes IsNot Nothing Then Return EditedBytes
            Return OriginalBytes
        End Get
    End Property

    Public Sub New(index As Integer, timestamp As DateTime, originalBytes As Byte(), originalLength As UInteger, info As PacketHeaderInfo)
        Me.Index = index
        Me.Timestamp = timestamp
        Me.OriginalBytes = originalBytes
        Me.OriginalLength = originalLength
        Me.Info = info
    End Sub

End Class
