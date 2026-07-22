Option Strict On
Option Explicit On

Imports System
Imports System.Collections.Generic
Imports System.IO
Imports System.Runtime.InteropServices
Imports System.Text

''' <summary>
''' Rappresenta un'interfaccia di rete restituita da pcap_findalldevs, con il
''' nome interno (da passare a pcap_open_live) e la descrizione leggibile.
''' </summary>
Public NotInheritable Class PcapDevice
    Public ReadOnly Property Name As String
    Public ReadOnly Property Description As String

    Public Sub New(name As String, description As String)
        Me.Name = name
        Me.Description = description
    End Sub

    Public Overrides Function ToString() As String
        If String.IsNullOrEmpty(Description) Then Return Name
        Return Description & "  [" & Name & "]"
    End Function
End Class

''' <summary>
''' Handle aperto su un'interfaccia con pcap_open_live, usato solo per inviare
''' pacchetti grezzi (pcap_sendpacket). Va racchiuso in Using/Dispose per
''' garantire la chiusura del driver Npcap.
''' </summary>
Public NotInheritable Class PcapSender
    Implements IDisposable

    Private _handle As IntPtr
    Private _disposed As Boolean = False

    Friend Sub New(handle As IntPtr)
        _handle = handle
    End Sub

    Public Sub Send(data As Byte())
        Dim result As Integer = WinPcap.SendRaw(_handle, data)
        If result <> 0 Then
            Throw New InvalidOperationException("pcap_sendpacket ha restituito un errore: " & WinPcap.GetLastError(_handle))
        End If
    End Sub

    Public Sub Dispose() Implements IDisposable.Dispose
        If Not _disposed Then
            If _handle <> IntPtr.Zero Then
                WinPcap.CloseHandle(_handle)
                _handle = IntPtr.Zero
            End If
            _disposed = True
        End If
    End Sub
End Class

''' <summary>
''' Wrapper P/Invoke minimale su wpcap.dll (Npcap installato in modalità
''' compatibile WinPcap), usato solo per enumerare le interfacce di rete e
''' inviare pacchetti raw così come sono stati letti/modificati dal pcap.
''' Npcap installa wpcap.dll/Packet.dll in %SystemRoot%\System32\Npcap, una
''' cartella che di norma NON è nel PATH di sistema: la aggiungiamo quindi
''' esplicitamente alla ricerca DLL del processo prima di ogni chiamata.
''' </summary>
Public NotInheritable Class WinPcap

    Private Sub New()
    End Sub

    Private Const PCAP_ERRBUF_SIZE As Integer = 256

    <DllImport("kernel32.dll", CharSet:=CharSet.Unicode, SetLastError:=True)>
    Private Shared Function SetDllDirectory(lpPathName As String) As Boolean
    End Function

    <StructLayout(LayoutKind.Sequential)>
    Private Structure pcap_if
        Public nextPtr As IntPtr
        Public name As IntPtr
        Public description As IntPtr
        Public addresses As IntPtr
        Public flags As UInteger
    End Structure

    <DllImport("wpcap.dll", CallingConvention:=CallingConvention.Cdecl, CharSet:=CharSet.Ansi)>
    Private Shared Function pcap_findalldevs(ByRef alldevs As IntPtr, errbuf As StringBuilder) As Integer
    End Function

    <DllImport("wpcap.dll", CallingConvention:=CallingConvention.Cdecl)>
    Private Shared Sub pcap_freealldevs(alldevs As IntPtr)
    End Sub

    <DllImport("wpcap.dll", CallingConvention:=CallingConvention.Cdecl, CharSet:=CharSet.Ansi)>
    Private Shared Function pcap_open_live(device As String, snaplen As Integer, promisc As Integer, to_ms As Integer, errbuf As StringBuilder) As IntPtr
    End Function

    <DllImport("wpcap.dll", CallingConvention:=CallingConvention.Cdecl)>
    Private Shared Function pcap_sendpacket(p As IntPtr, buf As Byte(), size As Integer) As Integer
    End Function

    <DllImport("wpcap.dll", CallingConvention:=CallingConvention.Cdecl)>
    Private Shared Sub pcap_close(p As IntPtr)
    End Sub

    <DllImport("wpcap.dll", CallingConvention:=CallingConvention.Cdecl)>
    Private Shared Function pcap_geterr(p As IntPtr) As IntPtr
    End Function

    Private Shared _dllDirReady As Boolean = False

    Public Shared Sub EnsureDllDirectory()
        If _dllDirReady Then Return
        Dim npcapDir As String = Path.Combine(Environment.SystemDirectory, "Npcap")
        If Directory.Exists(npcapDir) Then
            SetDllDirectory(npcapDir)
        End If
        _dllDirReady = True
    End Sub

    ''' <summary>
    ''' Enumera le interfacce di rete disponibili tramite pcap_findalldevs.
    ''' Richiede che Npcap (o WinPcap) sia installato; solitamente non
    ''' richiede privilegi elevati per la sola enumerazione.
    ''' </summary>
    Public Shared Function ListDevices() As List(Of PcapDevice)
        EnsureDllDirectory()
        Dim result As New List(Of PcapDevice)
        Dim errbuf As New StringBuilder(PCAP_ERRBUF_SIZE)
        Dim head As IntPtr = IntPtr.Zero

        If pcap_findalldevs(head, errbuf) <> 0 Then
            Throw New InvalidOperationException("pcap_findalldevs fallita: " & errbuf.ToString())
        End If

        Try
            Dim current As IntPtr = head
            While current <> IntPtr.Zero
                Dim dev As pcap_if = Marshal.PtrToStructure(Of pcap_if)(current)
                Dim name As String = If(dev.name <> IntPtr.Zero, Marshal.PtrToStringAnsi(dev.name), "")
                Dim desc As String = If(dev.description <> IntPtr.Zero, Marshal.PtrToStringAnsi(dev.description), "")
                result.Add(New PcapDevice(name, desc))
                current = dev.nextPtr
            End While
        Finally
            If head <> IntPtr.Zero Then pcap_freealldevs(head)
        End Try

        Return result
    End Function

    ''' <summary>
    ''' Apre l'interfaccia indicata in modalità invio. Se Npcap è installato in
    ''' modalità "solo amministratori" (l'impostazione predefinita) questa
    ''' chiamata fallisce se il processo non è elevato.
    ''' </summary>
    Public Shared Function OpenLive(deviceName As String, Optional snaplen As Integer = 65536, Optional promiscuous As Boolean = False, Optional timeoutMs As Integer = 1000) As PcapSender
        EnsureDllDirectory()
        Dim errbuf As New StringBuilder(PCAP_ERRBUF_SIZE)
        Dim handle As IntPtr = pcap_open_live(deviceName, snaplen, If(promiscuous, 1, 0), timeoutMs, errbuf)
        If handle = IntPtr.Zero Then
            Throw New InvalidOperationException("pcap_open_live fallita su '" & deviceName & "': " & errbuf.ToString())
        End If
        Return New PcapSender(handle)
    End Function

    Friend Shared Function SendRaw(handle As IntPtr, data As Byte()) As Integer
        Return pcap_sendpacket(handle, data, data.Length)
    End Function

    Friend Shared Function GetLastError(handle As IntPtr) As String
        Dim ptr As IntPtr = pcap_geterr(handle)
        If ptr = IntPtr.Zero Then Return ""
        Return Marshal.PtrToStringAnsi(ptr)
    End Function

    Friend Shared Sub CloseHandle(handle As IntPtr)
        pcap_close(handle)
    End Sub

End Class
