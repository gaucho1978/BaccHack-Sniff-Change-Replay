Option Strict On
Option Explicit On

Imports System
Imports System.ComponentModel
Imports System.Drawing
Imports System.Windows.Forms

Partial Public Class MainForm
    Inherits Form

    Private components As IContainer

    Friend WithEvents lblFile As Label
    Friend WithEvents txtFile As TextBox
    Friend WithEvents btnBrowse As Button

    Friend WithEvents lblAdapter As Label
    Friend WithEvents cmbAdapters As ComboBox
    Friend WithEvents btnRefreshAdapters As Button

    Friend WithEvents grpEdit As GroupBox
    Friend WithEvents chkDstMac As CheckBox
    Friend WithEvents txtOrigDstMac As TextBox
    Friend WithEvents lblArrowMac As Label
    Friend WithEvents txtNewDstMac As TextBox
    Friend WithEvents chkDstIp As CheckBox
    Friend WithEvents txtOrigDstIp As TextBox
    Friend WithEvents lblArrowIp As Label
    Friend WithEvents txtNewDstIp As TextBox
    Friend WithEvents chkDstUdpPort As CheckBox
    Friend WithEvents txtOrigDstUdpPort As TextBox
    Friend WithEvents lblArrowUdp As Label
    Friend WithEvents numNewDstUdpPort As NumericUpDown
    Friend WithEvents chkDstTcpPort As CheckBox
    Friend WithEvents txtOrigDstTcpPort As TextBox
    Friend WithEvents lblArrowTcp As Label
    Friend WithEvents numNewDstTcpPort As NumericUpDown
    Friend WithEvents chkSrcMac As CheckBox
    Friend WithEvents txtOrigSrcMac As TextBox
    Friend WithEvents lblArrowSrcMac As Label
    Friend WithEvents txtNewSrcMac As TextBox
    Friend WithEvents chkSrcIp As CheckBox
    Friend WithEvents txtOrigSrcIp As TextBox
    Friend WithEvents lblArrowSrcIp As Label
    Friend WithEvents txtNewSrcIp As TextBox
    Friend WithEvents chkSrcUdpPort As CheckBox
    Friend WithEvents txtOrigSrcUdpPort As TextBox
    Friend WithEvents lblArrowSrcUdp As Label
    Friend WithEvents numNewSrcUdpPort As NumericUpDown
    Friend WithEvents chkSrcTcpPort As CheckBox
    Friend WithEvents txtOrigSrcTcpPort As TextBox
    Friend WithEvents lblArrowSrcTcp As Label
    Friend WithEvents numNewSrcTcpPort As NumericUpDown
    Friend WithEvents btnApplyEdits As Button
    Friend WithEvents btnRevertEdits As Button
    Friend WithEvents lblEditStatus As Label

    Friend WithEvents grpReplay As GroupBox
    Friend WithEvents lblSpeed As Label
    Friend WithEvents txtSpeed As TextBox
    Friend WithEvents lblSpeedHint As Label
    Friend WithEvents chkIgnoreTiming As CheckBox
    Friend WithEvents lblMaxGap As Label
    Friend WithEvents numMaxGap As NumericUpDown
    Friend WithEvents chkContinueOnError As CheckBox
    Friend WithEvents btnPlay As Button
    Friend WithEvents btnPause As Button
    Friend WithEvents btnStop As Button

    Friend WithEvents progressPlayback As ProgressBar
    Friend WithEvents lblStatus As Label
    Friend WithEvents lstPackets As ListView
    Friend WithEvents txtLog As TextBox

    Protected Overrides Sub Dispose(disposing As Boolean)
        If disposing AndAlso components IsNot Nothing Then components.Dispose()
        MyBase.Dispose(disposing)
    End Sub

    Private Sub InitializeComponent()
        Me.lblFile = New Label()
        Me.txtFile = New TextBox()
        Me.btnBrowse = New Button()
        Me.lblAdapter = New Label()
        Me.cmbAdapters = New ComboBox()
        Me.btnRefreshAdapters = New Button()

        Me.grpEdit = New GroupBox()
        Me.chkDstMac = New CheckBox()
        Me.txtOrigDstMac = New TextBox()
        Me.lblArrowMac = New Label()
        Me.txtNewDstMac = New TextBox()
        Me.chkDstIp = New CheckBox()
        Me.txtOrigDstIp = New TextBox()
        Me.lblArrowIp = New Label()
        Me.txtNewDstIp = New TextBox()
        Me.chkDstUdpPort = New CheckBox()
        Me.txtOrigDstUdpPort = New TextBox()
        Me.lblArrowUdp = New Label()
        Me.numNewDstUdpPort = New NumericUpDown()
        Me.chkDstTcpPort = New CheckBox()
        Me.txtOrigDstTcpPort = New TextBox()
        Me.lblArrowTcp = New Label()
        Me.numNewDstTcpPort = New NumericUpDown()
        Me.chkSrcMac = New CheckBox()
        Me.txtOrigSrcMac = New TextBox()
        Me.lblArrowSrcMac = New Label()
        Me.txtNewSrcMac = New TextBox()
        Me.chkSrcIp = New CheckBox()
        Me.txtOrigSrcIp = New TextBox()
        Me.lblArrowSrcIp = New Label()
        Me.txtNewSrcIp = New TextBox()
        Me.chkSrcUdpPort = New CheckBox()
        Me.txtOrigSrcUdpPort = New TextBox()
        Me.lblArrowSrcUdp = New Label()
        Me.numNewSrcUdpPort = New NumericUpDown()
        Me.chkSrcTcpPort = New CheckBox()
        Me.txtOrigSrcTcpPort = New TextBox()
        Me.lblArrowSrcTcp = New Label()
        Me.numNewSrcTcpPort = New NumericUpDown()
        Me.btnApplyEdits = New Button()
        Me.btnRevertEdits = New Button()
        Me.lblEditStatus = New Label()

        Me.grpReplay = New GroupBox()
        Me.lblSpeed = New Label()
        Me.txtSpeed = New TextBox()
        Me.lblSpeedHint = New Label()
        Me.chkIgnoreTiming = New CheckBox()
        Me.lblMaxGap = New Label()
        Me.numMaxGap = New NumericUpDown()
        Me.chkContinueOnError = New CheckBox()
        Me.btnPlay = New Button()
        Me.btnPause = New Button()
        Me.btnStop = New Button()

        Me.progressPlayback = New ProgressBar()
        Me.lblStatus = New Label()
        Me.lstPackets = New ListView()
        Me.txtLog = New TextBox()

        CType(Me.numNewDstUdpPort, ISupportInitialize).BeginInit()
        CType(Me.numNewDstTcpPort, ISupportInitialize).BeginInit()
        CType(Me.numNewSrcUdpPort, ISupportInitialize).BeginInit()
        CType(Me.numNewSrcTcpPort, ISupportInitialize).BeginInit()
        CType(Me.numMaxGap, ISupportInitialize).BeginInit()
        Me.grpEdit.SuspendLayout()
        Me.grpReplay.SuspendLayout()
        Me.SuspendLayout()
        '
        ' lblFile
        '
        Me.lblFile.AutoSize = True
        Me.lblFile.Location = New Point(12, 18)
        Me.lblFile.Text = "File pcap:"
        '
        ' txtFile
        '
        Me.txtFile.Location = New Point(110, 15)
        Me.txtFile.Size = New Size(628, 22)
        Me.txtFile.ReadOnly = True
        Me.txtFile.Anchor = CType(AnchorStyles.Top Or AnchorStyles.Left Or AnchorStyles.Right, AnchorStyles)
        '
        ' btnBrowse
        '
        Me.btnBrowse.Location = New Point(748, 13)
        Me.btnBrowse.Size = New Size(140, 26)
        Me.btnBrowse.Text = "Apri file .pcap..."
        Me.btnBrowse.Anchor = CType(AnchorStyles.Top Or AnchorStyles.Right, AnchorStyles)
        '
        ' lblAdapter
        '
        Me.lblAdapter.AutoSize = True
        Me.lblAdapter.Location = New Point(12, 51)
        Me.lblAdapter.Text = "Interfaccia di invio:"
        '
        ' cmbAdapters
        '
        Me.cmbAdapters.Location = New Point(150, 48)
        Me.cmbAdapters.Size = New Size(628, 23)
        Me.cmbAdapters.DropDownStyle = ComboBoxStyle.DropDownList
        Me.cmbAdapters.Anchor = CType(AnchorStyles.Top Or AnchorStyles.Left Or AnchorStyles.Right, AnchorStyles)
        '
        ' btnRefreshAdapters
        '
        Me.btnRefreshAdapters.Location = New Point(788, 46)
        Me.btnRefreshAdapters.Size = New Size(100, 26)
        Me.btnRefreshAdapters.Text = "Aggiorna"
        Me.btnRefreshAdapters.Anchor = CType(AnchorStyles.Top Or AnchorStyles.Right, AnchorStyles)
        '
        ' grpEdit
        '
        Me.grpEdit.Location = New Point(12, 85)
        Me.grpEdit.Size = New Size(876, 210)
        Me.grpEdit.Text = "Modifica pacchetti prima dell'invio (solo i pacchetti con il valore ORIGINALE indicato vengono cambiati; vuoto = tutti)"
        Me.grpEdit.Anchor = CType(AnchorStyles.Top Or AnchorStyles.Left Or AnchorStyles.Right, AnchorStyles)
        Me.grpEdit.Controls.Add(Me.chkDstMac)
        Me.grpEdit.Controls.Add(Me.txtOrigDstMac)
        Me.grpEdit.Controls.Add(Me.lblArrowMac)
        Me.grpEdit.Controls.Add(Me.txtNewDstMac)
        Me.grpEdit.Controls.Add(Me.chkDstIp)
        Me.grpEdit.Controls.Add(Me.txtOrigDstIp)
        Me.grpEdit.Controls.Add(Me.lblArrowIp)
        Me.grpEdit.Controls.Add(Me.txtNewDstIp)
        Me.grpEdit.Controls.Add(Me.chkDstUdpPort)
        Me.grpEdit.Controls.Add(Me.txtOrigDstUdpPort)
        Me.grpEdit.Controls.Add(Me.lblArrowUdp)
        Me.grpEdit.Controls.Add(Me.numNewDstUdpPort)
        Me.grpEdit.Controls.Add(Me.chkDstTcpPort)
        Me.grpEdit.Controls.Add(Me.txtOrigDstTcpPort)
        Me.grpEdit.Controls.Add(Me.lblArrowTcp)
        Me.grpEdit.Controls.Add(Me.numNewDstTcpPort)
        Me.grpEdit.Controls.Add(Me.chkSrcMac)
        Me.grpEdit.Controls.Add(Me.txtOrigSrcMac)
        Me.grpEdit.Controls.Add(Me.lblArrowSrcMac)
        Me.grpEdit.Controls.Add(Me.txtNewSrcMac)
        Me.grpEdit.Controls.Add(Me.chkSrcIp)
        Me.grpEdit.Controls.Add(Me.txtOrigSrcIp)
        Me.grpEdit.Controls.Add(Me.lblArrowSrcIp)
        Me.grpEdit.Controls.Add(Me.txtNewSrcIp)
        Me.grpEdit.Controls.Add(Me.chkSrcUdpPort)
        Me.grpEdit.Controls.Add(Me.txtOrigSrcUdpPort)
        Me.grpEdit.Controls.Add(Me.lblArrowSrcUdp)
        Me.grpEdit.Controls.Add(Me.numNewSrcUdpPort)
        Me.grpEdit.Controls.Add(Me.chkSrcTcpPort)
        Me.grpEdit.Controls.Add(Me.txtOrigSrcTcpPort)
        Me.grpEdit.Controls.Add(Me.lblArrowSrcTcp)
        Me.grpEdit.Controls.Add(Me.numNewSrcTcpPort)
        Me.grpEdit.Controls.Add(Me.btnApplyEdits)
        Me.grpEdit.Controls.Add(Me.btnRevertEdits)
        Me.grpEdit.Controls.Add(Me.lblEditStatus)
        '
        ' chkDstMac
        '
        Me.chkDstMac.AutoSize = True
        Me.chkDstMac.Location = New Point(15, 46)
        Me.chkDstMac.Text = "MAC dest.:"
        '
        ' txtOrigDstMac
        '
        Me.txtOrigDstMac.Location = New Point(140, 43)
        Me.txtOrigDstMac.Size = New Size(130, 22)
        '
        ' lblArrowMac
        '
        Me.lblArrowMac.AutoSize = True
        Me.lblArrowMac.Location = New Point(275, 46)
        Me.lblArrowMac.Text = "->"
        '
        ' txtNewDstMac
        '
        Me.txtNewDstMac.Location = New Point(300, 43)
        Me.txtNewDstMac.Size = New Size(130, 22)
        '
        ' chkDstIp
        '
        Me.chkDstIp.AutoSize = True
        Me.chkDstIp.Location = New Point(450, 46)
        Me.chkDstIp.Text = "IP dest.:"
        '
        ' txtOrigDstIp
        '
        Me.txtOrigDstIp.Location = New Point(545, 43)
        Me.txtOrigDstIp.Size = New Size(110, 22)
        '
        ' lblArrowIp
        '
        Me.lblArrowIp.AutoSize = True
        Me.lblArrowIp.Location = New Point(660, 46)
        Me.lblArrowIp.Text = "->"
        '
        ' txtNewDstIp
        '
        Me.txtNewDstIp.Location = New Point(685, 43)
        Me.txtNewDstIp.Size = New Size(110, 22)
        '
        ' chkDstUdpPort
        '
        Me.chkDstUdpPort.AutoSize = True
        Me.chkDstUdpPort.Location = New Point(15, 76)
        Me.chkDstUdpPort.Text = "Porta UDP dest.:"
        '
        ' txtOrigDstUdpPort
        '
        Me.txtOrigDstUdpPort.Location = New Point(160, 73)
        Me.txtOrigDstUdpPort.Size = New Size(70, 22)
        '
        ' lblArrowUdp
        '
        Me.lblArrowUdp.AutoSize = True
        Me.lblArrowUdp.Location = New Point(235, 76)
        Me.lblArrowUdp.Text = "->"
        '
        ' numNewDstUdpPort
        '
        Me.numNewDstUdpPort.Location = New Point(260, 74)
        Me.numNewDstUdpPort.Size = New Size(80, 22)
        Me.numNewDstUdpPort.Minimum = New Decimal(New Integer() {0, 0, 0, 0})
        Me.numNewDstUdpPort.Maximum = New Decimal(New Integer() {65535, 0, 0, 0})
        '
        ' chkDstTcpPort
        '
        Me.chkDstTcpPort.AutoSize = True
        Me.chkDstTcpPort.Location = New Point(450, 76)
        Me.chkDstTcpPort.Text = "Porta TCP dest.:"
        '
        ' txtOrigDstTcpPort
        '
        Me.txtOrigDstTcpPort.Location = New Point(595, 73)
        Me.txtOrigDstTcpPort.Size = New Size(70, 22)
        '
        ' lblArrowTcp
        '
        Me.lblArrowTcp.AutoSize = True
        Me.lblArrowTcp.Location = New Point(670, 76)
        Me.lblArrowTcp.Text = "->"
        '
        ' numNewDstTcpPort
        '
        Me.numNewDstTcpPort.Location = New Point(695, 74)
        Me.numNewDstTcpPort.Size = New Size(80, 22)
        Me.numNewDstTcpPort.Minimum = New Decimal(New Integer() {0, 0, 0, 0})
        Me.numNewDstTcpPort.Maximum = New Decimal(New Integer() {65535, 0, 0, 0})
        '
        ' chkSrcMac
        '
        Me.chkSrcMac.AutoSize = True
        Me.chkSrcMac.Location = New Point(15, 106)
        Me.chkSrcMac.Text = "MAC mitt.:"
        '
        ' txtOrigSrcMac
        '
        Me.txtOrigSrcMac.Location = New Point(140, 103)
        Me.txtOrigSrcMac.Size = New Size(130, 22)
        '
        ' lblArrowSrcMac
        '
        Me.lblArrowSrcMac.AutoSize = True
        Me.lblArrowSrcMac.Location = New Point(275, 106)
        Me.lblArrowSrcMac.Text = "->"
        '
        ' txtNewSrcMac
        '
        Me.txtNewSrcMac.Location = New Point(300, 103)
        Me.txtNewSrcMac.Size = New Size(130, 22)
        '
        ' chkSrcIp
        '
        Me.chkSrcIp.AutoSize = True
        Me.chkSrcIp.Location = New Point(450, 106)
        Me.chkSrcIp.Text = "IP mitt.:"
        '
        ' txtOrigSrcIp
        '
        Me.txtOrigSrcIp.Location = New Point(545, 103)
        Me.txtOrigSrcIp.Size = New Size(110, 22)
        '
        ' lblArrowSrcIp
        '
        Me.lblArrowSrcIp.AutoSize = True
        Me.lblArrowSrcIp.Location = New Point(660, 106)
        Me.lblArrowSrcIp.Text = "->"
        '
        ' txtNewSrcIp
        '
        Me.txtNewSrcIp.Location = New Point(685, 103)
        Me.txtNewSrcIp.Size = New Size(110, 22)
        '
        ' chkSrcUdpPort
        '
        Me.chkSrcUdpPort.AutoSize = True
        Me.chkSrcUdpPort.Location = New Point(15, 136)
        Me.chkSrcUdpPort.Text = "Porta UDP mitt.:"
        '
        ' txtOrigSrcUdpPort
        '
        Me.txtOrigSrcUdpPort.Location = New Point(160, 133)
        Me.txtOrigSrcUdpPort.Size = New Size(70, 22)
        '
        ' lblArrowSrcUdp
        '
        Me.lblArrowSrcUdp.AutoSize = True
        Me.lblArrowSrcUdp.Location = New Point(235, 136)
        Me.lblArrowSrcUdp.Text = "->"
        '
        ' numNewSrcUdpPort
        '
        Me.numNewSrcUdpPort.Location = New Point(260, 134)
        Me.numNewSrcUdpPort.Size = New Size(80, 22)
        Me.numNewSrcUdpPort.Minimum = New Decimal(New Integer() {0, 0, 0, 0})
        Me.numNewSrcUdpPort.Maximum = New Decimal(New Integer() {65535, 0, 0, 0})
        '
        ' chkSrcTcpPort
        '
        Me.chkSrcTcpPort.AutoSize = True
        Me.chkSrcTcpPort.Location = New Point(450, 136)
        Me.chkSrcTcpPort.Text = "Porta TCP mitt.:"
        '
        ' txtOrigSrcTcpPort
        '
        Me.txtOrigSrcTcpPort.Location = New Point(595, 133)
        Me.txtOrigSrcTcpPort.Size = New Size(70, 22)
        '
        ' lblArrowSrcTcp
        '
        Me.lblArrowSrcTcp.AutoSize = True
        Me.lblArrowSrcTcp.Location = New Point(670, 136)
        Me.lblArrowSrcTcp.Text = "->"
        '
        ' numNewSrcTcpPort
        '
        Me.numNewSrcTcpPort.Location = New Point(695, 134)
        Me.numNewSrcTcpPort.Size = New Size(80, 22)
        Me.numNewSrcTcpPort.Minimum = New Decimal(New Integer() {0, 0, 0, 0})
        Me.numNewSrcTcpPort.Maximum = New Decimal(New Integer() {65535, 0, 0, 0})
        '
        ' btnApplyEdits
        '
        Me.btnApplyEdits.Location = New Point(15, 168)
        Me.btnApplyEdits.Size = New Size(230, 26)
        Me.btnApplyEdits.Text = "Applica ai pacchetti"
        '
        ' btnRevertEdits
        '
        Me.btnRevertEdits.Location = New Point(255, 168)
        Me.btnRevertEdits.Size = New Size(150, 26)
        Me.btnRevertEdits.Text = "Ripristina originali"
        '
        ' lblEditStatus
        '
        Me.lblEditStatus.AutoSize = True
        Me.lblEditStatus.Location = New Point(420, 174)
        Me.lblEditStatus.Text = "0 pacchetti modificati"
        Me.lblEditStatus.ForeColor = Color.DarkSlateGray
        '
        ' grpReplay
        '
        Me.grpReplay.Location = New Point(12, 305)
        Me.grpReplay.Size = New Size(876, 150)
        Me.grpReplay.Text = "Replay"
        Me.grpReplay.Anchor = CType(AnchorStyles.Top Or AnchorStyles.Left Or AnchorStyles.Right, AnchorStyles)
        Me.grpReplay.Controls.Add(Me.lblSpeed)
        Me.grpReplay.Controls.Add(Me.txtSpeed)
        Me.grpReplay.Controls.Add(Me.lblSpeedHint)
        Me.grpReplay.Controls.Add(Me.chkIgnoreTiming)
        Me.grpReplay.Controls.Add(Me.lblMaxGap)
        Me.grpReplay.Controls.Add(Me.numMaxGap)
        Me.grpReplay.Controls.Add(Me.chkContinueOnError)
        Me.grpReplay.Controls.Add(Me.btnPlay)
        Me.grpReplay.Controls.Add(Me.btnPause)
        Me.grpReplay.Controls.Add(Me.btnStop)
        '
        ' lblSpeed
        '
        Me.lblSpeed.AutoSize = True
        Me.lblSpeed.Location = New Point(15, 28)
        Me.lblSpeed.Text = "Velocita:"
        '
        ' txtSpeed
        '
        Me.txtSpeed.Location = New Point(85, 25)
        Me.txtSpeed.Size = New Size(60, 22)
        Me.txtSpeed.Text = "1.0"
        '
        ' lblSpeedHint
        '
        Me.lblSpeedHint.AutoSize = True
        Me.lblSpeedHint.Location = New Point(155, 28)
        Me.lblSpeedHint.Text = "(1 = tempo reale; 2 = doppia velocita; 0.5 = meta velocita)"
        Me.lblSpeedHint.ForeColor = Color.DarkSlateGray
        '
        ' chkIgnoreTiming
        '
        Me.chkIgnoreTiming.AutoSize = True
        Me.chkIgnoreTiming.Location = New Point(15, 58)
        Me.chkIgnoreTiming.Text = "Invia il piu veloce possibile (ignora i tempi originali)"
        '
        ' lblMaxGap
        '
        Me.lblMaxGap.AutoSize = True
        Me.lblMaxGap.Location = New Point(15, 90)
        Me.lblMaxGap.Text = "Pausa massima tra pacchetti (ms, 0 = nessun limite):"
        '
        ' numMaxGap
        '
        Me.numMaxGap.Location = New Point(345, 87)
        Me.numMaxGap.Size = New Size(90, 22)
        Me.numMaxGap.Minimum = New Decimal(New Integer() {0, 0, 0, 0})
        Me.numMaxGap.Maximum = New Decimal(New Integer() {600000, 0, 0, 0})
        Me.numMaxGap.Increment = New Decimal(New Integer() {100, 0, 0, 0})
        '
        ' chkContinueOnError
        '
        Me.chkContinueOnError.AutoSize = True
        Me.chkContinueOnError.Location = New Point(460, 90)
        Me.chkContinueOnError.Text = "Continua anche in caso di errore di invio"
        '
        ' btnPlay
        '
        Me.btnPlay.Location = New Point(15, 118)
        Me.btnPlay.Size = New Size(90, 28)
        Me.btnPlay.Text = "Play"
        '
        ' btnPause
        '
        Me.btnPause.Location = New Point(115, 118)
        Me.btnPause.Size = New Size(90, 28)
        Me.btnPause.Text = "Pausa"
        Me.btnPause.Enabled = False
        '
        ' btnStop
        '
        Me.btnStop.Location = New Point(215, 118)
        Me.btnStop.Size = New Size(90, 28)
        Me.btnStop.Text = "Stop"
        Me.btnStop.Enabled = False
        '
        ' progressPlayback
        '
        Me.progressPlayback.Location = New Point(12, 465)
        Me.progressPlayback.Size = New Size(876, 22)
        Me.progressPlayback.Anchor = CType(AnchorStyles.Top Or AnchorStyles.Left Or AnchorStyles.Right, AnchorStyles)
        '
        ' lblStatus
        '
        Me.lblStatus.AutoSize = True
        Me.lblStatus.Location = New Point(12, 491)
        Me.lblStatus.Text = "Pronto."
        Me.lblStatus.ForeColor = Color.DarkSlateGray
        '
        ' lstPackets
        '
        Me.lstPackets.Location = New Point(12, 518)
        Me.lstPackets.Size = New Size(876, 235)
        Me.lstPackets.Anchor = CType(AnchorStyles.Top Or AnchorStyles.Bottom Or AnchorStyles.Left Or AnchorStyles.Right, AnchorStyles)
        '
        ' txtLog
        '
        Me.txtLog.Location = New Point(12, 763)
        Me.txtLog.Size = New Size(876, 110)
        Me.txtLog.Multiline = True
        Me.txtLog.ReadOnly = True
        Me.txtLog.ScrollBars = ScrollBars.Vertical
        Me.txtLog.Font = New Font("Consolas", 8.5F)
        Me.txtLog.Anchor = CType(AnchorStyles.Bottom Or AnchorStyles.Left Or AnchorStyles.Right, AnchorStyles)
        '
        ' MainForm
        '
        Me.AutoScaleMode = AutoScaleMode.Font
        Me.AutoScroll = True
        Me.ClientSize = New Size(900, 885)
        Me.Controls.Add(Me.lblFile)
        Me.Controls.Add(Me.txtFile)
        Me.Controls.Add(Me.btnBrowse)
        Me.Controls.Add(Me.lblAdapter)
        Me.Controls.Add(Me.cmbAdapters)
        Me.Controls.Add(Me.btnRefreshAdapters)
        Me.Controls.Add(Me.grpEdit)
        Me.Controls.Add(Me.grpReplay)
        Me.Controls.Add(Me.progressPlayback)
        Me.Controls.Add(Me.lblStatus)
        Me.Controls.Add(Me.lstPackets)
        Me.Controls.Add(Me.txtLog)
        Me.MinimumSize = New Size(760, 500)
        Me.Text = "Bacchack Sniff&Change&Replay"

        CType(Me.numNewDstUdpPort, ISupportInitialize).EndInit()
        CType(Me.numNewDstTcpPort, ISupportInitialize).EndInit()
        CType(Me.numNewSrcUdpPort, ISupportInitialize).EndInit()
        CType(Me.numNewSrcTcpPort, ISupportInitialize).EndInit()
        CType(Me.numMaxGap, ISupportInitialize).EndInit()
        Me.grpEdit.ResumeLayout(False)
        Me.grpEdit.PerformLayout()
        Me.grpReplay.ResumeLayout(False)
        Me.grpReplay.PerformLayout()
        Me.ResumeLayout(False)
        Me.PerformLayout()
    End Sub

End Class
