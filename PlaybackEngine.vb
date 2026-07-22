Option Strict On
Option Explicit On

Imports System
Imports System.Collections.Generic
Imports System.Diagnostics
Imports System.Threading
Imports System.Threading.Tasks

''' <summary>
''' Motore di replay: invia i pacchetti nell'ordine in cui compaiono nel file,
''' rispettando (con un eventuale fattore di velocità) l'intervallo di tempo
''' reale tra un pacchetto e il successivo calcolato dai timestamp originali
''' del pcap. Gira su un thread separato; gli eventi vengono sollevati su
''' quello stesso thread e vanno marshalizzati sulla UI da chi li gestisce.
''' </summary>
Public NotInheritable Class PlaybackEngine

    Public Event PacketSent(index As Integer, total As Integer, packet As PcapPacket)
    Public Event PacketSendFailed(index As Integer, total As Integer, packet As PcapPacket, message As String)
    Public Event PlaybackFinished(wasCancelled As Boolean, failedCount As Integer)
    Public Event PlaybackError(message As String)

    Private _cts As CancellationTokenSource
    Private ReadOnly _pauseEvent As New ManualResetEventSlim(True)
    Private _running As Boolean = False

    Public ReadOnly Property IsRunning As Boolean
        Get
            Return _running
        End Get
    End Property

    Public Sub Start(packets As IReadOnlyList(Of PcapPacket), sender As PcapSender, speedMultiplier As Double, ignoreTiming As Boolean, maxGapMs As Integer, continueOnSendError As Boolean)
        If _running Then Return
        _running = True
        _cts = New CancellationTokenSource()
        _pauseEvent.Set()
        Dim token As CancellationToken = _cts.Token

        Task.Run(Sub() RunLoop(packets, sender, speedMultiplier, ignoreTiming, maxGapMs, continueOnSendError, token))
    End Sub

    Private Sub RunLoop(packets As IReadOnlyList(Of PcapPacket), sender As PcapSender, speedMultiplier As Double, ignoreTiming As Boolean, maxGapMs As Integer, continueOnSendError As Boolean, token As CancellationToken)
        Dim cancelled As Boolean = False
        Dim failedCount As Integer = 0
        Try
            Dim sw As New Stopwatch()
            For i As Integer = 0 To packets.Count - 1
                token.ThrowIfCancellationRequested()
                _pauseEvent.Wait(token)

                If i > 0 AndAlso Not ignoreTiming Then
                    Dim deltaMs As Double = (packets(i).Timestamp - packets(i - 1).Timestamp).TotalMilliseconds
                    If deltaMs < 0 Then deltaMs = 0
                    If maxGapMs > 0 AndAlso deltaMs > maxGapMs Then deltaMs = maxGapMs
                    deltaMs = deltaMs / Math.Max(speedMultiplier, 0.001)

                    If deltaMs > 0 Then
                        sw.Restart()
                        While sw.Elapsed.TotalMilliseconds < deltaMs
                            token.ThrowIfCancellationRequested()
                            _pauseEvent.Wait(token)
                            Dim remaining As Double = deltaMs - sw.Elapsed.TotalMilliseconds
                            If remaining > 0 Then Thread.Sleep(CInt(Math.Min(remaining, 20)))
                        End While
                    End If
                End If

                token.ThrowIfCancellationRequested()
                Try
                    sender.Send(packets(i).BytesToSend)
                    RaiseEvent PacketSent(i, packets.Count, packets(i))
                Catch sendEx As Exception
                    failedCount += 1
                    RaiseEvent PacketSendFailed(i, packets.Count, packets(i), sendEx.Message)
                    If Not continueOnSendError Then Throw
                End Try
            Next
        Catch ex As OperationCanceledException
            cancelled = True
        Catch ex As Exception
            RaiseEvent PlaybackError(ex.Message)
        Finally
            _running = False
            RaiseEvent PlaybackFinished(cancelled, failedCount)
        End Try
    End Sub

    Public Sub Pause()
        _pauseEvent.Reset()
    End Sub

    Public Sub ResumePlayback()
        _pauseEvent.Set()
    End Sub

    Public Sub StopPlayback()
        If _cts IsNot Nothing Then
            _pauseEvent.Set() ' sblocca eventuali attese in pausa così Cancel viene visto subito
            _cts.Cancel()
        End If
    End Sub

End Class
