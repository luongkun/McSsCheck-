using System;
using System.Drawing;
using System.Runtime.Versioning;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using McSsCheck.Models;
using McSsCheck.Reports;
using McSsCheck.Util;

namespace McSsCheck.Gui;

/// <summary>
/// Main WinForms window. Three logical states are folded onto the same
/// surface (no tab control / no wizard) so the user always sees the live
/// log:
///
///   Idle    — consent text shown, "Start scan" enabled.
///   Running — progress bar + status label live, "Cancel" enabled.
///   Done    — "Open HTML report" enabled, "Close" enabled.
///
/// The form does *no* scanning itself; it only renders state pushed in by
/// <see cref="GuiHost"/> via <see cref="AppendLine"/>, <see cref="SetStatus"/>,
/// <see cref="SetProgress"/>, etc. Every state-mutating call is safe from any
/// thread — they marshal to the UI thread internally.
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed class MainForm : Form
{
    public enum LineKind { Banner, Section, Info, Ok, Warn, Hit, Error, Dim }

    // ----- styling -----
    private static readonly Color BgColor      = Color.FromArgb(14, 17, 22);
    private static readonly Color Bg2Color     = Color.FromArgb(19, 24, 32);
    private static readonly Color FgColor      = Color.FromArgb(230, 230, 230);
    private static readonly Color DimColor     = Color.FromArgb(170, 170, 170);
    private static readonly Color HitColor     = Color.FromArgb(255, 108, 108);
    private static readonly Color WarnColor    = Color.FromArgb(245, 217, 124);
    private static readonly Color OkColor      = Color.FromArgb(108, 230, 160);
    private static readonly Color InfoColor    = Color.FromArgb(108, 182, 255);
    private static readonly Color BannerColor  = Color.FromArgb(180, 220, 255);
    private static readonly Color SectionColor = Color.FromArgb(245, 217, 124);
    private static readonly Color AccentColor  = Color.FromArgb(60, 120, 200);

    private readonly Label        _title;
    private readonly Label        _status;
    private readonly ProgressBar  _progress;
    private readonly RichTextBox  _log;
    private readonly Button       _btnStart;
    private readonly Button       _btnCancel;
    private readonly Button       _btnOpenReport;
    private readonly Button       _btnClose;

    private string? _htmlReportPath;
    private CancellationTokenSource? _cts;

    public event EventHandler? StartRequested;
    public event EventHandler? CancelRequested;

    public MainForm(string version)
    {
        Text                = $"McSsCheck v{version} — Minecraft screenshare helper";
        StartPosition       = FormStartPosition.CenterScreen;
        MinimumSize         = new Size(820, 560);
        Size                = new Size(960, 700);
        BackColor           = BgColor;
        ForeColor           = FgColor;
        Font                = new Font("Segoe UI", 9F);

        _title = new Label
        {
            Text      = $"McSsCheck v{version}",
            Dock      = DockStyle.Top,
            Height    = 56,
            ForeColor = BannerColor,
            BackColor = Bg2Color,
            TextAlign = ContentAlignment.MiddleLeft,
            Padding   = new Padding(16, 0, 0, 0),
            Font      = new Font("Segoe UI", 14F, FontStyle.Bold),
        };

        _status = new Label
        {
            Text      = "Ready. Click \"Start scan\" after the player gives explicit consent.",
            Dock      = DockStyle.Top,
            Height    = 32,
            ForeColor = DimColor,
            BackColor = Bg2Color,
            TextAlign = ContentAlignment.MiddleLeft,
            Padding   = new Padding(16, 0, 16, 0),
        };

        _progress = new ProgressBar
        {
            Dock    = DockStyle.Top,
            Height  = 10,
            Minimum = 0,
            Maximum = 100,
            Value   = 0,
            Style   = ProgressBarStyle.Continuous,
        };

        _log = new RichTextBox
        {
            Dock         = DockStyle.Fill,
            ReadOnly     = true,
            BackColor    = BgColor,
            ForeColor    = FgColor,
            BorderStyle  = BorderStyle.None,
            Font         = new Font("Cascadia Mono", 9F, FontStyle.Regular,
                                    GraphicsUnit.Point, 0,
                                    /* fall back if Cascadia not present */ false),
            DetectUrls   = false,
            HideSelection = false,
            WordWrap     = false,
            ScrollBars   = RichTextBoxScrollBars.ForcedBoth,
        };
        // Fallback font if Cascadia Mono isn't installed.
        try
        {
            using var probe = new Font("Cascadia Mono", 9F);
            if (!string.Equals(probe.Name, "Cascadia Mono", StringComparison.OrdinalIgnoreCase))
                _log.Font = new Font("Consolas", 9.5F);
        }
        catch { _log.Font = new Font("Consolas", 9.5F); }

        var btnPanel = new FlowLayoutPanel
        {
            Dock           = DockStyle.Bottom,
            Height         = 56,
            BackColor      = Bg2Color,
            FlowDirection  = FlowDirection.RightToLeft,
            Padding        = new Padding(8),
            WrapContents   = false,
        };

        _btnStart      = MakeButton("Start scan",       primary: true);
        _btnCancel     = MakeButton("Cancel",           primary: false);
        _btnOpenReport = MakeButton("Open HTML report", primary: false);
        _btnClose      = MakeButton("Close",            primary: false);

        _btnStart.Click      += (_, __) => StartRequested?.Invoke(this, EventArgs.Empty);
        _btnCancel.Click     += (_, __) => { _cts?.Cancel(); CancelRequested?.Invoke(this, EventArgs.Empty); };
        _btnOpenReport.Click += (_, __) =>
        {
            if (!string.IsNullOrEmpty(_htmlReportPath))
                HtmlReportRenderer.OpenInBrowser(_htmlReportPath);
        };
        _btnClose.Click += (_, __) => Close();

        // RTL flow → reverse the visual order: Close | Open Report | Cancel | Start
        btnPanel.Controls.Add(_btnClose);
        btnPanel.Controls.Add(_btnOpenReport);
        btnPanel.Controls.Add(_btnCancel);
        btnPanel.Controls.Add(_btnStart);

        Controls.Add(_log);
        Controls.Add(btnPanel);
        Controls.Add(_progress);
        Controls.Add(_status);
        Controls.Add(_title);

        SetState(UiState.Idle);
        AppendLine("Welcome.", LineKind.Banner);
        AppendLine(
            "This tool inspects local artifacts that well-known Minecraft cheat\n" +
            "clients leave behind. It is read-only. Network calls are optional\n" +
            "(Modrinth hash verification + opt-in VirusTotal). No telemetry.\n" +
            "Click \"Start scan\" once the player has given explicit consent on\n" +
            "voice + with their full desktop visible.", LineKind.Info);
    }

    private static Button MakeButton(string text, bool primary)
    {
        var b = new Button
        {
            Text      = text,
            Width     = 140,
            Height    = 36,
            FlatStyle = FlatStyle.Flat,
            BackColor = primary ? AccentColor : Bg2Color,
            ForeColor = Color.White,
            Font      = new Font("Segoe UI", 9.5F, primary ? FontStyle.Bold : FontStyle.Regular),
            Margin    = new Padding(6, 4, 0, 4),
            Cursor    = Cursors.Hand,
        };
        b.FlatAppearance.BorderColor = primary
            ? Color.FromArgb(80, 160, 240)
            : Color.FromArgb(60, 70, 90);
        b.FlatAppearance.BorderSize  = 1;
        return b;
    }

    private enum UiState { Idle, Running, Done, Cancelled, Failed }

    private void SetState(UiState s)
    {
        switch (s)
        {
            case UiState.Idle:
                _btnStart.Enabled      = true;
                _btnCancel.Enabled     = false;
                _btnOpenReport.Enabled = false;
                _btnClose.Enabled      = true;
                break;
            case UiState.Running:
                _btnStart.Enabled      = false;
                _btnCancel.Enabled     = true;
                _btnOpenReport.Enabled = false;
                _btnClose.Enabled      = false;
                break;
            case UiState.Done:
                _btnStart.Enabled      = false;
                _btnCancel.Enabled     = false;
                _btnOpenReport.Enabled = !string.IsNullOrEmpty(_htmlReportPath);
                _btnClose.Enabled      = true;
                break;
            case UiState.Cancelled:
            case UiState.Failed:
                _btnStart.Enabled      = false;
                _btnCancel.Enabled     = false;
                _btnOpenReport.Enabled = !string.IsNullOrEmpty(_htmlReportPath);
                _btnClose.Enabled      = true;
                break;
        }
    }

    /// <summary>Mark the start of a scan. Caller passes a CTS so the form's
    /// Cancel button can request cancellation.</summary>
    public void NotifyScanStarted(CancellationTokenSource cts)
    {
        UiInvoke(() =>
        {
            _cts = cts;
            SetState(UiState.Running);
            _progress.Style    = ProgressBarStyle.Marquee;
            _progress.Maximum  = 100;
            _progress.Value    = 0;
        });
    }

    public void NotifyScanFinished(bool cancelled, string? htmlPath)
    {
        UiInvoke(() =>
        {
            _htmlReportPath = htmlPath;
            _progress.Style = ProgressBarStyle.Continuous;
            _progress.Value = _progress.Maximum;
            SetState(cancelled ? UiState.Cancelled : UiState.Done);
            if (cancelled)
                SetStatus("Scan cancelled.");
            else
                SetStatus("Scan complete." + (htmlPath != null ? " Click \"Open HTML report\" to view." : ""));
        });
    }

    public void NotifyScanFailed(string message)
    {
        UiInvoke(() =>
        {
            _progress.Style = ProgressBarStyle.Continuous;
            SetState(UiState.Failed);
            SetStatus("Scan failed: " + message);
        });
    }

    public void SetStatus(string text)
    {
        UiInvoke(() => _status.Text = "  " + text);
    }

    public void SetProgress(int currentStep, int totalSteps, string stepTitle)
    {
        UiInvoke(() =>
        {
            if (totalSteps <= 0)
            {
                _progress.Style = ProgressBarStyle.Marquee;
                return;
            }
            _progress.Style    = ProgressBarStyle.Continuous;
            _progress.Maximum  = totalSteps;
            _progress.Value    = Math.Max(0, Math.Min(currentStep, totalSteps));
            _status.Text       = $"  [{currentStep}/{totalSteps}] {stepTitle}";
        });
    }

    public void AppendLine(string text, LineKind kind)
    {
        UiInvoke(() =>
        {
            // Pre-format the prefix+colour the same way the console does.
            string line;
            Color  color;
            switch (kind)
            {
                case LineKind.Banner:
                    AppendColored("\n" + new string('=', 78) + "\n", BannerColor);
                    AppendColored(" " + text + "\n",                  BannerColor);
                    AppendColored(new string('=', 78) + "\n",         BannerColor);
                    return;
                case LineKind.Section:
                    line = $"\n--- {text} ---\n"; color = SectionColor; break;
                case LineKind.Ok:
                    line = $"  [OK] {text}\n";    color = OkColor;     break;
                case LineKind.Warn:
                    line = $"  [!]  {text}\n";    color = WarnColor;   break;
                case LineKind.Hit:
                    line = $"  [HIT] {text}\n";   color = HitColor;    break;
                case LineKind.Error:
                    line = $"  [ERR] {text}\n";   color = HitColor;    break;
                case LineKind.Dim:
                    line = $"  {text}\n";         color = DimColor;    break;
                case LineKind.Info:
                default:
                    line = $"  {text}\n";         color = FgColor;     break;
            }
            AppendColored(line, color);
        });
    }

    private void AppendColored(string text, Color color)
    {
        // RichTextBox APIs must run on the UI thread; UiInvoke handles that.
        _log.SelectionStart  = _log.TextLength;
        _log.SelectionLength = 0;
        _log.SelectionColor  = color;
        _log.AppendText(text);
        _log.SelectionColor  = _log.ForeColor;
        _log.SelectionStart  = _log.TextLength;
        _log.ScrollToCaret();
    }

    private void UiInvoke(Action a)
    {
        if (IsDisposed) return;
        if (InvokeRequired) { try { BeginInvoke(a); } catch (ObjectDisposedException) { } }
        else                a();
    }

    /// <summary>Disable Cancel during the consent flow's modal phase so the
    /// user can't trigger a cancel before scan even starts.</summary>
    public void ResetIdle()
    {
        UiInvoke(() => SetState(UiState.Idle));
    }
}
