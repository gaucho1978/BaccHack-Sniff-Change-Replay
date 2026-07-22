Option Strict On
Option Explicit On

Imports System
Imports System.Globalization
Imports System.IO
Imports System.Linq
Imports System.Net
Imports System.Windows.Forms

''' <summary>
''' Form principale. Permette di:
'''  1) aprire un file pcap classico (salvato da Wireshark) e vederne i pacchetti;
'''  2) definire regole di modifica (MAC/IP/porta di destinazione) e applicarle
'''     a tutti i pacchetti caricati;
'''  3) selezionare un'interfaccia di rete (via Npcap) e rifare il replay dei
'''     pacchetti (originali o modificati) rispettando la tempistica originale.
''' </summary>
Partial Public Class MainForm

    Private _packets As New List(Of PcapPacket)
    Private _linkType As UInteger
    Private _sender As PcapSender
    Private ReadOnly _engine As New PlaybackEngine()
    Private ReadOnly _rules As New EditRules()
    Private _paused As Boolean = False

    Public Sub New()
        InitializeComponent()
        ConfigureListView()

        AddHandler btnBrowse.Click, AddressOf OnBrowse
        AddHandler btnRefreshAdapters.Click, AddressOf OnRefreshAdapters
        AddHandler btnApplyEdits.Click, AddressOf OnApplyEdits
        AddHandler btnRevertEdits.Click, AddressOf OnRevertEdits
        AddHandler btnPlay.Click, AddressOf OnPlay
        AddHandler btnPause.Click, AddressOf OnPause
        AddHandler btnStop.Click, AddressOf OnStop
        AddHandler lstPackets.RetrieveVirtualItem, AddressOf OnRetrieveItem

        AddHandler _engine.PacketSent, AddressOf OnEnginePacketSent
        AddHandler _engine.PacketSendFailed, AddressOf OnEnginePacketSendFailed
        AddHandler _engine.PlaybackFinished, AddressOf OnEnginePlaybackFinished
        AddHandler _engine.PlaybackError, AddressOf OnEnginePlaybackError

        HookAutoCheck(txtOrigDstMac, chkDstMac)
        HookAutoCheck(txtNewDstMac, chkDstMac)
        HookAutoCheck(txtOrigDstIp, chkDstIp)
        HookAutoCheck(txtNewDstIp, chkDstIp)
        HookAutoCheck(txtOrigDstUdpPort, chkDstUdpPort)
        HookAutoCheck(numNewDstUdpPort, chkDstUdpPort)
        HookAutoCheck(txtOrigDstTcpPort, chkDstTcpPort)
        HookAutoCheck(numNewDstTcpPort, chkDstTcpPort)
        HookAutoCheck(txtOrigSrcMac, chkSrcMac)
        HookAutoCheck(txtNewSrcMac, chkSrcMac)
        HookAutoCheck(txtOrigSrcIp, chkSrcIp)
        HookAutoCheck(txtNewSrcIp, chkSrcIp)
        HookAutoCheck(txtOrigSrcUdpPort, chkSrcUdpPort)
        HookAutoCheck(numNewSrcUdpPort, chkSrcUdpPort)
        HookAutoCheck(txtOrigSrcTcpPort, chkSrcTcpPort)
        HookAutoCheck(numNewSrcTcpPort, chkSrcTcpPort)

        SetPlaybackUiState(False)
        UpdateEditStatusLabel()
        OnRefreshAdapters(Me, EventArgs.Empty)
    End Sub

    ''' <summary>
    ''' Collega un controllo di input (TextBox o NumericUpDown) a una checkbox:
    ''' non appena l'utente digita qualcosa, la regola corrispondente viene
    ''' automaticamente abilitata (la checkbox non viene mai deselezionata in
    ''' automatico: per disabilitare la regola l'utente la togglia a mano).
    ''' </summary>
    Private Sub HookAutoCheck(inputControl As Control, checkbox As CheckBox)
        AddHandler inputControl.TextChanged, Sub(sender As Object, e As EventArgs) checkbox.Checked = True
    End Sub

    Private Sub ConfigureListView()
        lstPackets.View = View.Details
        lstPackets.FullRowSelect = True
        lstPackets.GridLines = True
        lstPackets.VirtualMode = True
        lstPackets.Font = New Drawing.Font("Consolas", 9.0F)
        lstPackets.Columns.Add("#", 55)
        lstPackets.Columns.Add("Ora", 110)
        lstPackets.Columns.Add("Delta t (ms)", 80)
        lstPackets.Columns.Add("MAC sorg.", 130)
        lstPackets.Columns.Add("MAC dest.", 130)
        lstPackets.Columns.Add("IP sorg.", 110)
        lstPackets.Columns.Add("IP dest.", 110)
        lstPackets.Columns.Add("Proto", 60)
        lstPackets.Columns.Add("Porta sorg.", 80)
        lstPackets.Columns.Add("Porta dest.", 80)
        lstPackets.Columns.Add("Lunghezza", 80)
        lstPackets.Columns.Add("Modificato", 80)
    End Sub

    ' ---------------------------------------------------------------------
    ' Caricamento file pcap
    ' ---------------------------------------------------------------------

    Private Sub OnBrowse(sender As Object, e As EventArgs)
        If _engine.IsRunning Then
            MessageBox.Show(Me, "Ferma il replay in corso prima di caricare un altro file.", "Replay in corso", MessageBoxButtons.OK, MessageBoxIcon.Warning)
            Return
        End If

        Using dlg As New OpenFileDialog()
            dlg.Filter = "File pcap (*.pcap;*.cap)|*.pcap;*.cap|Tutti i file (*.*)|*.*"
            dlg.Title = "Seleziona una sniffata salvata da Wireshark (formato pcap classico)"
            If dlg.ShowDialog(Me) = DialogResult.OK Then
                LoadPcapFile(dlg.FileName)
            End If
        End Using
    End Sub

    Private Sub LoadPcapFile(path As String)
        Try
            Dim lt As UInteger = 0
            Dim pkts As List(Of PcapPacket) = PcapFileReader.ReadFile(path, lt)

            _packets = pkts
            _linkType = lt
            txtFile.Text = path

            lstPackets.VirtualListSize = 0
            lstPackets.VirtualListSize = _packets.Count
            lstPackets.Invalidate()

            AppendLog($"Caricati {_packets.Count} pacchetti da '{System.IO.Path.GetFileName(path)}' (link-layer type={_linkType}).")
            If _linkType <> 1 Then
                AppendLog("Attenzione: il link-layer del file non è Ethernet: l'editing dei campi non è disponibile, ma il replay dei byte grezzi funziona comunque.")
            End If

            UpdateEditStatusLabel()
            lblStatus.Text = $"{_packets.Count} pacchetti caricati."
        Catch ex As Exception
            MessageBox.Show(Me, ex.Message, "Errore durante il caricamento del file", MessageBoxButtons.OK, MessageBoxIcon.Error)
        End Try
    End Sub

    ' ---------------------------------------------------------------------
    ' Interfacce di rete (Npcap)
    ' ---------------------------------------------------------------------

    Private Sub OnRefreshAdapters(sender As Object, e As EventArgs)
        Try
            Dim selectedName As String = Nothing
            Dim previous As PcapDevice = TryCast(cmbAdapters.SelectedItem, PcapDevice)
            If previous IsNot Nothing Then selectedName = previous.Name

            cmbAdapters.Items.Clear()
            Dim devices As List(Of PcapDevice) = WinPcap.ListDevices()
            For Each d As PcapDevice In devices
                cmbAdapters.Items.Add(d)
            Next

            If devices.Count = 0 Then
                AppendLog("Nessuna interfaccia di rete trovata da Npcap.")
            Else
                Dim indexToSelect As Integer = 0
                If selectedName IsNot Nothing Then
                    Dim idx As Integer = devices.FindIndex(Function(d) d.Name = selectedName)
                    If idx >= 0 Then indexToSelect = idx
                End If
                cmbAdapters.SelectedIndex = indexToSelect
            End If
        Catch ex As Exception
            AppendLog("Errore nell'enumerazione delle interfacce di rete: " & ex.Message & " (verifica che Npcap sia installato).")
        End Try
    End Sub

    ' ---------------------------------------------------------------------
    ' Regole di modifica
    ' ---------------------------------------------------------------------

    Private Sub SyncRulesFromUi()
        _rules.EnableDstMac = chkDstMac.Checked
        _rules.OriginalDstMacText = txtOrigDstMac.Text.Trim()
        _rules.NewDstMacText = txtNewDstMac.Text.Trim()
        _rules.EnableDstIp = chkDstIp.Checked
        _rules.OriginalDstIpText = txtOrigDstIp.Text.Trim()
        _rules.NewDstIpText = txtNewDstIp.Text.Trim()
        _rules.EnableDstUdpPort = chkDstUdpPort.Checked
        _rules.OriginalDstUdpPortText = txtOrigDstUdpPort.Text.Trim()
        _rules.NewDstUdpPort = CUShort(numNewDstUdpPort.Value)
        _rules.EnableDstTcpPort = chkDstTcpPort.Checked
        _rules.OriginalDstTcpPortText = txtOrigDstTcpPort.Text.Trim()
        _rules.NewDstTcpPort = CUShort(numNewDstTcpPort.Value)

        _rules.EnableSrcMac = chkSrcMac.Checked
        _rules.OriginalSrcMacText = txtOrigSrcMac.Text.Trim()
        _rules.NewSrcMacText = txtNewSrcMac.Text.Trim()
        _rules.EnableSrcIp = chkSrcIp.Checked
        _rules.OriginalSrcIpText = txtOrigSrcIp.Text.Trim()
        _rules.NewSrcIpText = txtNewSrcIp.Text.Trim()
        _rules.EnableSrcUdpPort = chkSrcUdpPort.Checked
        _rules.OriginalSrcUdpPortText = txtOrigSrcUdpPort.Text.Trim()
        _rules.NewSrcUdpPort = CUShort(numNewSrcUdpPort.Value)
        _rules.EnableSrcTcpPort = chkSrcTcpPort.Checked
        _rules.OriginalSrcTcpPortText = txtOrigSrcTcpPort.Text.Trim()
        _rules.NewSrcTcpPort = CUShort(numNewSrcTcpPort.Value)
    End Sub

    Private Sub OnApplyEdits(sender As Object, e As EventArgs)
        If _packets.Count = 0 Then
            MessageBox.Show(Me, "Carica prima un file pcap.", "Nessun pacchetto caricato", MessageBoxButtons.OK, MessageBoxIcon.Information)
            Return
        End If

        SyncRulesFromUi()

        Dim errorMessage As String = Nothing
        If Not _rules.Validate(errorMessage) Then
            MessageBox.Show(Me, errorMessage, "Regole non valide", MessageBoxButtons.OK, MessageBoxIcon.Warning)
            Return
        End If

        Dim changed As Integer = 0
        For Each p As PcapPacket In _packets
            p.EditedBytes = PacketEditor.ApplyEdits(p.OriginalBytes, p.Info, _rules)
            If p.IsEdited Then changed += 1
        Next

        lstPackets.Invalidate()
        UpdateEditStatusLabel()
        AppendLog($"Modifiche applicate: {changed} di {_packets.Count} pacchetti modificati.")
    End Sub

    Private Sub OnRevertEdits(sender As Object, e As EventArgs)
        For Each p As PcapPacket In _packets
            p.EditedBytes = Nothing
        Next
        lstPackets.Invalidate()
        UpdateEditStatusLabel()
        AppendLog("Modifiche annullate: ripristinati i pacchetti originali.")
    End Sub

    Private Sub UpdateEditStatusLabel()
        Dim n As Integer = _packets.Where(Function(p) p.IsEdited).Count()
        lblEditStatus.Text = $"{n} pacchetti modificati"
    End Sub

    ' ---------------------------------------------------------------------
    ' Replay
    ' ---------------------------------------------------------------------

    Private Sub OnPlay(sender As Object, e As EventArgs)
        If _engine.IsRunning Then Return

        If _packets.Count = 0 Then
            MessageBox.Show(Me, "Carica prima un file pcap.", "Nessun pacchetto caricato", MessageBoxButtons.OK, MessageBoxIcon.Information)
            Return
        End If

        Dim device As PcapDevice = TryCast(cmbAdapters.SelectedItem, PcapDevice)
        If device Is Nothing Then
            MessageBox.Show(Me, "Seleziona un'interfaccia di rete su cui inviare i pacchetti.", "Nessuna interfaccia selezionata", MessageBoxButtons.OK, MessageBoxIcon.Information)
            Return
        End If

        Try
            CloseSenderIfOpen()
            _sender = WinPcap.OpenLive(device.Name)
        Catch ex As Exception
            MessageBox.Show(Me,
                ex.Message & Environment.NewLine & Environment.NewLine &
                "Suggerimento: Npcap richiede tipicamente privilegi di amministratore per l'invio di pacchetti raw. Prova ad eseguire il programma come amministratore.",
                "Impossibile aprire l'interfaccia", MessageBoxButtons.OK, MessageBoxIcon.Error)
            Return
        End Try

        Dim speed As Double
        If Not Double.TryParse(txtSpeed.Text.Trim(), NumberStyles.Float, CultureInfo.InvariantCulture, speed) OrElse speed <= 0 Then
            speed = 1.0
            txtSpeed.Text = "1.0"
        End If

        Dim ignoreTiming As Boolean = chkIgnoreTiming.Checked
        Dim maxGap As Integer = CInt(numMaxGap.Value)
        Dim continueOnError As Boolean = chkContinueOnError.Checked

        SetPlaybackUiState(True)
        progressPlayback.Minimum = 0
        progressPlayback.Maximum = Math.Max(_packets.Count, 1)
        progressPlayback.Value = 0
        _paused = False
        btnPause.Text = "Pausa"

        AppendLog($"Avvio replay: {_packets.Count} pacchetti su '{device}', velocità={speed.ToString("0.##", CultureInfo.InvariantCulture)}x{If(ignoreTiming, " (timing ignorato)", "")}.")
        _engine.Start(_packets, _sender, speed, ignoreTiming, maxGap, continueOnError)
    End Sub

    Private Sub OnPause(sender As Object, e As EventArgs)
        If Not _engine.IsRunning Then Return
        _paused = Not _paused
        If _paused Then
            _engine.Pause()
            btnPause.Text = "Riprendi"
            AppendLog("Replay in pausa.")
        Else
            _engine.ResumePlayback()
            btnPause.Text = "Pausa"
            AppendLog("Replay ripreso.")
        End If
    End Sub

    Private Sub OnStop(sender As Object, e As EventArgs)
        _engine.StopPlayback()
    End Sub

    Private Sub SetPlaybackUiState(playing As Boolean)
        btnPlay.Enabled = Not playing
        btnBrowse.Enabled = Not playing
        btnApplyEdits.Enabled = Not playing
        btnRevertEdits.Enabled = Not playing
        btnPause.Enabled = playing
        btnStop.Enabled = playing
    End Sub

    Private Sub CloseSenderIfOpen()
        If _sender IsNot Nothing Then
            _sender.Dispose()
            _sender = Nothing
        End If
    End Sub

    ' ---------------------------------------------------------------------
    ' Eventi del motore di replay (sollevati su un thread di background)
    ' ---------------------------------------------------------------------

    Private Sub OnEnginePacketSent(index As Integer, total As Integer, packet As PcapPacket)
        If Me.InvokeRequired Then
            Me.BeginInvoke(New Action(Of Integer, Integer, PcapPacket)(AddressOf OnEnginePacketSent), index, total, packet)
            Return
        End If

        progressPlayback.Value = Math.Min(index + 1, progressPlayback.Maximum)
        lblStatus.Text = $"Pacchetto {index + 1}/{total} inviato ({packet.Timestamp:HH:mm:ss.fff})."

        If index Mod 10 = 0 OrElse index = total - 1 Then
            Dim tag As String = If(packet.IsEdited, " [modificato]", "")
            AppendLog($"#{index + 1}/{total} inviato @ {packet.Timestamp:HH:mm:ss.fff} ({packet.BytesToSend.Length} byte){tag}")
        End If
    End Sub

    Private Sub OnEnginePacketSendFailed(index As Integer, total As Integer, packet As PcapPacket, message As String)
        If Me.InvokeRequired Then
            Me.BeginInvoke(New Action(Of Integer, Integer, PcapPacket, String)(AddressOf OnEnginePacketSendFailed), index, total, packet, message)
            Return
        End If

        AppendLog($"#{index + 1}/{total} FALLITO @ {packet.Timestamp:HH:mm:ss.fff}: {message}")
    End Sub

    Private Sub OnEnginePlaybackFinished(wasCancelled As Boolean, failedCount As Integer)
        If Me.InvokeRequired Then
            Me.BeginInvoke(New Action(Of Boolean, Integer)(AddressOf OnEnginePlaybackFinished), wasCancelled, failedCount)
            Return
        End If

        SetPlaybackUiState(False)
        lblStatus.Text = If(wasCancelled, "Replay interrotto dall'utente.", "Replay completato.")
        If failedCount > 0 Then
            lblStatus.Text &= $" ({failedCount} pacchetti falliti)"
        End If
        AppendLog(lblStatus.Text)
    End Sub

    Private Sub OnEnginePlaybackError(message As String)
        If Me.InvokeRequired Then
            Me.BeginInvoke(New Action(Of String)(AddressOf OnEnginePlaybackError), message)
            Return
        End If

        AppendLog("ERRORE durante il replay: " & message)
        MessageBox.Show(Me, message, "Errore durante il replay", MessageBoxButtons.OK, MessageBoxIcon.Error)
    End Sub

    ' ---------------------------------------------------------------------
    ' Griglia pacchetti (virtual mode)
    ' ---------------------------------------------------------------------

    Private Sub OnRetrieveItem(sender As Object, e As RetrieveVirtualItemEventArgs)
        Dim idx As Integer = e.ItemIndex
        Dim p As PcapPacket = _packets(idx)
        Dim info As PacketHeaderInfo = p.Info

        Dim deltaText As String = "-"
        If idx > 0 Then
            Dim deltaMs As Double = (p.Timestamp - _packets(idx - 1).Timestamp).TotalMilliseconds
            deltaText = deltaMs.ToString("F1", CultureInfo.InvariantCulture)
        End If

        Dim item As New ListViewItem((idx + 1).ToString(CultureInfo.InvariantCulture))
        item.SubItems.Add(p.Timestamp.ToString("HH:mm:ss.fff", CultureInfo.InvariantCulture))
        item.SubItems.Add(deltaText)
        item.SubItems.Add(FormatMac(info.SrcMac))
        item.SubItems.Add(FormatMac(info.DstMac))
        item.SubItems.Add(FormatIp(info.SrcIp))
        item.SubItems.Add(FormatIp(info.DstIp))
        item.SubItems.Add(info.ProtocolName())
        item.SubItems.Add(If(info.HasTransport, info.SrcPort.ToString(CultureInfo.InvariantCulture), ""))
        item.SubItems.Add(If(info.HasTransport, info.DstPort.ToString(CultureInfo.InvariantCulture), ""))
        item.SubItems.Add(p.BytesToSend.Length.ToString(CultureInfo.InvariantCulture))
        item.SubItems.Add(If(p.IsEdited, "Si", ""))

        e.Item = item
    End Sub

    Private Shared Function FormatMac(bytes As Byte()) As String
        If bytes Is Nothing Then Return ""
        Return String.Join(":", bytes.Select(Function(b) b.ToString("X2", CultureInfo.InvariantCulture)))
    End Function

    Private Shared Function FormatIp(bytes As Byte()) As String
        If bytes Is Nothing Then Return ""
        Return New IPAddress(bytes).ToString()
    End Function

    ' ---------------------------------------------------------------------
    ' Log
    ' ---------------------------------------------------------------------

    Private Sub AppendLog(text As String)
        Dim line As String = $"[{DateTime.Now:HH:mm:ss}] {text}"
        txtLog.AppendText(line & Environment.NewLine)

        If txtLog.Lines.Length > 4000 Then
            Dim keep As String() = txtLog.Lines.Skip(txtLog.Lines.Length - 2000).ToArray()
            txtLog.Text = String.Join(Environment.NewLine, keep)
            txtLog.SelectionStart = txtLog.TextLength
            txtLog.ScrollToCaret()
        End If
    End Sub

    Protected Overrides Sub OnFormClosing(e As FormClosingEventArgs)
        If _engine.IsRunning Then _engine.StopPlayback()
        CloseSenderIfOpen()
        MyBase.OnFormClosing(e)
    End Sub

End Class
