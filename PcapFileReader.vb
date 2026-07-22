Option Strict On
Option Explicit On

Imports System
Imports System.Collections.Generic
Imports System.IO

''' <summary>
''' Lettore del formato "libpcap classico" (quello prodotto da Wireshark/tcpdump
''' con estensione .pcap, salvato scegliendo esplicitamente il formato
''' "libpcap"). Non supporta pcapng (il formato a blocchi, spesso .pcapng, che
''' è l'impostazione predefinita delle versioni recenti di Wireshark).
''' </summary>
Public NotInheritable Class PcapFileReader

    Private Sub New()
    End Sub

    ''' <summary>
    ''' Legge tutti i pacchetti dal file indicato. In <paramref name="linkType"/>
    ''' viene restituito il tipo di link-layer dichiarato nell'header globale
    ''' (1 = Ethernet, l'unico attualmente supportato per il parsing dei campi).
    ''' </summary>
    Public Shared Function ReadFile(path As String, ByRef linkType As UInteger) As List(Of PcapPacket)
        Using fs As New FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read)
            Using br As New BinaryReader(fs)
                Dim magic As UInteger = br.ReadUInt32()
                Dim swapEndian As Boolean
                Dim nanoResolution As Boolean

                Select Case magic
                    Case &HA1B2C3D4UI
                        swapEndian = False
                        nanoResolution = False
                    Case &HD4C3B2A1UI
                        swapEndian = True
                        nanoResolution = False
                    Case &HA1B23C4DUI
                        swapEndian = False
                        nanoResolution = True
                    Case &H4D3CB2A1UI
                        swapEndian = True
                        nanoResolution = True
                    Case Else
                        Throw New InvalidDataException(
                            "Il file non è un pcap classico riconosciuto (magic number non valido)." & vbCrLf &
                            "Se è stato salvato in formato pcapng, risalvalo da Wireshark con ""File > Salva con nome"" scegliendo il formato ""Wireshark/tcpdump/... - pcap"".")
                End Select

                ReadU16(br, swapEndian) ' version_major
                ReadU16(br, swapEndian) ' version_minor
                ReadU32(br, swapEndian) ' thiszone (correzione GMT->locale, in genere 0)
                ReadU32(br, swapEndian) ' sigfigs (accuratezza timestamp, in genere 0)
                ReadU32(br, swapEndian) ' snaplen
                linkType = ReadU32(br, swapEndian)

                Dim packets As New List(Of PcapPacket)
                Dim idx As Integer = 0

                While fs.Position < fs.Length
                    If fs.Length - fs.Position < 16 Then Exit While

                    Dim tsSec As UInteger = ReadU32(br, swapEndian)
                    Dim tsFrac As UInteger = ReadU32(br, swapEndian)
                    Dim inclLen As UInteger = ReadU32(br, swapEndian)
                    Dim origLen As UInteger = ReadU32(br, swapEndian)

                    If inclLen > 200000000UI Then
                        Throw New InvalidDataException("Lunghezza di un pacchetto non plausibile nel file pcap: il file potrebbe essere troncato o corrotto.")
                    End If

                    Dim data As Byte() = br.ReadBytes(CInt(inclLen))
                    If data.Length < CInt(inclLen) Then Exit While ' file troncato a metà pacchetto

                    Dim micros As UInteger = If(nanoResolution, tsFrac \ 1000UI, tsFrac)
                    Dim ts As DateTime = DateTimeOffset.FromUnixTimeSeconds(CLng(tsSec)).UtcDateTime.AddTicks(CLng(micros) * 10L)

                    Dim info As PacketHeaderInfo = PacketEditor.ParseHeaders(data, linkType)
                    packets.Add(New PcapPacket(idx, ts, data, origLen, info))
                    idx += 1
                End While

                Return packets
            End Using
        End Using
    End Function

    Private Shared Function ReadU16(br As BinaryReader, swap As Boolean) As UShort
        Dim v As UShort = br.ReadUInt16()
        If Not swap Then Return v
        Dim lo As Integer = CInt(v) And &HFF
        Dim hi As Integer = (CInt(v) >> 8) And &HFF
        Return CType((lo << 8) Or hi, UShort)
    End Function

    Private Shared Function ReadU32(br As BinaryReader, swap As Boolean) As UInteger
        Dim v As UInteger = br.ReadUInt32()
        If swap Then Return SwapU32(v)
        Return v
    End Function

    Private Shared Function SwapU32(v As UInteger) As UInteger
        Return ((v And &HFFUI) << 24) Or ((v And &HFF00UI) << 8) Or ((v >> 8) And &HFF00UI) Or ((v >> 24) And &HFFUI)
    End Function

End Class
