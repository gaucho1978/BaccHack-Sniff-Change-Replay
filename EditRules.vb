Option Strict On
Option Explicit On

Imports System
Imports System.Globalization
Imports System.Net
Imports System.Net.Sockets

''' <summary>
''' Regole di modifica configurate dall'utente, applicate ai pacchetti caricati
''' prima del replay: MAC/IP/porta di destinazione E mittente. Ogni regola è
''' indipendente e opzionale, e per ciascuna si specifica sia il valore
''' ORIGINALE da cercare sia il NUOVO valore con cui sostituirlo: solo i
''' pacchetti il cui campo corrisponde al valore originale vengono modificati,
''' gli altri restano invariati. Se il valore originale è lasciato vuoto, la
''' regola si applica a tutti i pacchetti che hanno quel campo (comportamento
''' "qualsiasi").
''' </summary>
Public NotInheritable Class EditRules

    Public Property EnableDstMac As Boolean
    Public Property OriginalDstMacText As String = ""
    Public Property NewDstMacText As String = ""

    ''' <summary>Nothing = nessun filtro (si applica a qualsiasi MAC originale).</summary>
    Public ReadOnly Property OriginalDstMacBytes As Byte()
        Get
            Return ParseMac(OriginalDstMacText)
        End Get
    End Property

    Public ReadOnly Property NewDstMacBytes As Byte()
        Get
            Return ParseMac(NewDstMacText)
        End Get
    End Property

    Public Property EnableSrcMac As Boolean
    Public Property OriginalSrcMacText As String = ""
    Public Property NewSrcMacText As String = ""

    Public ReadOnly Property OriginalSrcMacBytes As Byte()
        Get
            Return ParseMac(OriginalSrcMacText)
        End Get
    End Property

    Public ReadOnly Property NewSrcMacBytes As Byte()
        Get
            Return ParseMac(NewSrcMacText)
        End Get
    End Property

    Public Property EnableDstIp As Boolean
    Public Property OriginalDstIpText As String = ""
    Public Property NewDstIpText As String = ""

    Public ReadOnly Property OriginalDstIpBytes As Byte()
        Get
            Return ParseIp(OriginalDstIpText)
        End Get
    End Property

    Public ReadOnly Property NewDstIpBytes As Byte()
        Get
            Return ParseIp(NewDstIpText)
        End Get
    End Property

    Public Property EnableSrcIp As Boolean
    Public Property OriginalSrcIpText As String = ""
    Public Property NewSrcIpText As String = ""

    Public ReadOnly Property OriginalSrcIpBytes As Byte()
        Get
            Return ParseIp(OriginalSrcIpText)
        End Get
    End Property

    Public ReadOnly Property NewSrcIpBytes As Byte()
        Get
            Return ParseIp(NewSrcIpText)
        End Get
    End Property

    Public Property EnableDstUdpPort As Boolean
    Public Property OriginalDstUdpPortText As String = ""
    Public Property NewDstUdpPort As UShort

    Public ReadOnly Property OriginalDstUdpPort As UShort?
        Get
            Return ParsePort(OriginalDstUdpPortText)
        End Get
    End Property

    Public Property EnableSrcUdpPort As Boolean
    Public Property OriginalSrcUdpPortText As String = ""
    Public Property NewSrcUdpPort As UShort

    Public ReadOnly Property OriginalSrcUdpPort As UShort?
        Get
            Return ParsePort(OriginalSrcUdpPortText)
        End Get
    End Property

    Public Property EnableDstTcpPort As Boolean
    Public Property OriginalDstTcpPortText As String = ""
    Public Property NewDstTcpPort As UShort

    Public ReadOnly Property OriginalDstTcpPort As UShort?
        Get
            Return ParsePort(OriginalDstTcpPortText)
        End Get
    End Property

    Public Property EnableSrcTcpPort As Boolean
    Public Property OriginalSrcTcpPortText As String = ""
    Public Property NewSrcTcpPort As UShort

    Public ReadOnly Property OriginalSrcTcpPort As UShort?
        Get
            Return ParsePort(OriginalSrcTcpPortText)
        End Get
    End Property

    ''' <summary>
    ''' Valida i campi delle sole regole abilitate. Ritorna False e valorizza
    ''' errorMessage se qualcosa non è nel formato atteso.
    ''' </summary>
    Public Function Validate(ByRef errorMessage As String) As Boolean
        If EnableDstMac Then
            If NewDstMacBytes Is Nothing Then
                errorMessage = "Nuovo MAC di destinazione non valido (formato atteso: AA:BB:CC:DD:EE:FF)."
                Return False
            End If
            If Not String.IsNullOrWhiteSpace(OriginalDstMacText) AndAlso OriginalDstMacBytes Is Nothing Then
                errorMessage = "MAC di destinazione originale non valido (formato atteso: AA:BB:CC:DD:EE:FF, oppure lascia vuoto per qualsiasi)."
                Return False
            End If
        End If

        If EnableSrcMac Then
            If NewSrcMacBytes Is Nothing Then
                errorMessage = "Nuovo MAC mittente non valido (formato atteso: AA:BB:CC:DD:EE:FF)."
                Return False
            End If
            If Not String.IsNullOrWhiteSpace(OriginalSrcMacText) AndAlso OriginalSrcMacBytes Is Nothing Then
                errorMessage = "MAC mittente originale non valido (formato atteso: AA:BB:CC:DD:EE:FF, oppure lascia vuoto per qualsiasi)."
                Return False
            End If
        End If

        If EnableDstIp Then
            If NewDstIpBytes Is Nothing Then
                errorMessage = "Nuovo IP di destinazione non valido (deve essere un indirizzo IPv4)."
                Return False
            End If
            If Not String.IsNullOrWhiteSpace(OriginalDstIpText) AndAlso OriginalDstIpBytes Is Nothing Then
                errorMessage = "IP di destinazione originale non valido (deve essere un indirizzo IPv4, oppure lascia vuoto per qualsiasi)."
                Return False
            End If
        End If

        If EnableSrcIp Then
            If NewSrcIpBytes Is Nothing Then
                errorMessage = "Nuovo IP mittente non valido (deve essere un indirizzo IPv4)."
                Return False
            End If
            If Not String.IsNullOrWhiteSpace(OriginalSrcIpText) AndAlso OriginalSrcIpBytes Is Nothing Then
                errorMessage = "IP mittente originale non valido (deve essere un indirizzo IPv4, oppure lascia vuoto per qualsiasi)."
                Return False
            End If
        End If

        If EnableDstUdpPort AndAlso Not String.IsNullOrWhiteSpace(OriginalDstUdpPortText) AndAlso Not OriginalDstUdpPort.HasValue Then
            errorMessage = "Porta UDP destinazione originale non valida (deve essere un numero 0-65535, oppure lascia vuoto per qualsiasi)."
            Return False
        End If

        If EnableSrcUdpPort AndAlso Not String.IsNullOrWhiteSpace(OriginalSrcUdpPortText) AndAlso Not OriginalSrcUdpPort.HasValue Then
            errorMessage = "Porta UDP mittente originale non valida (deve essere un numero 0-65535, oppure lascia vuoto per qualsiasi)."
            Return False
        End If

        If EnableDstTcpPort AndAlso Not String.IsNullOrWhiteSpace(OriginalDstTcpPortText) AndAlso Not OriginalDstTcpPort.HasValue Then
            errorMessage = "Porta TCP destinazione originale non valida (deve essere un numero 0-65535, oppure lascia vuoto per qualsiasi)."
            Return False
        End If

        If EnableSrcTcpPort AndAlso Not String.IsNullOrWhiteSpace(OriginalSrcTcpPortText) AndAlso Not OriginalSrcTcpPort.HasValue Then
            errorMessage = "Porta TCP mittente originale non valida (deve essere un numero 0-65535, oppure lascia vuoto per qualsiasi)."
            Return False
        End If

        errorMessage = Nothing
        Return True
    End Function

    Private Shared Function ParseMac(text As String) As Byte()
        If String.IsNullOrWhiteSpace(text) Then Return Nothing
        Dim parts As String() = text.Split({":"c, "-"c}, StringSplitOptions.RemoveEmptyEntries)
        If parts.Length <> 6 Then Return Nothing
        Dim result(5) As Byte
        For i As Integer = 0 To 5
            Dim b As Byte
            If Not Byte.TryParse(parts(i), NumberStyles.HexNumber, CultureInfo.InvariantCulture, b) Then Return Nothing
            result(i) = b
        Next
        Return result
    End Function

    Private Shared Function ParseIp(text As String) As Byte()
        If String.IsNullOrWhiteSpace(text) Then Return Nothing
        Dim addr As IPAddress = Nothing
        If IPAddress.TryParse(text, addr) AndAlso addr.AddressFamily = AddressFamily.InterNetwork Then
            Return addr.GetAddressBytes()
        End If
        Return Nothing
    End Function

    Private Shared Function ParsePort(text As String) As UShort?
        If String.IsNullOrWhiteSpace(text) Then Return Nothing
        Dim value As UShort
        If UShort.TryParse(text.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, value) Then Return value
        Return Nothing
    End Function

End Class
