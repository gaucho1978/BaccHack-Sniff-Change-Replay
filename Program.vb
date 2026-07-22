Option Strict On
Option Explicit On

Imports System
Imports System.Windows.Forms

''' <summary>
''' Punto di ingresso dell'applicazione WinForms.
''' Per essere riconosciuto come startup object dal compilatore VB.NET con
''' MyType=WindowsFormsWithCustomSubMain, il Sub deve essere Public,
''' marcato STAThread e contenuto in un Module.
''' </summary>
Public Module Program

    <STAThread()>
    Public Sub Main()
        Application.EnableVisualStyles()
        Application.SetCompatibleTextRenderingDefault(False)
        Application.Run(New MainForm())
    End Sub

End Module
