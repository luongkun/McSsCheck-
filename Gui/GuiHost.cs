using System;
using System.Runtime.Versioning;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using McSsCheck.Models;
using McSsCheck.Reports;
using McSsCheck.Util;

namespace McSsCheck.Gui;

/// <summary>
/// Bootstraps the WinForms host: builds <see cref="MainForm"/>, wires up
/// the start button to <see cref="ScanOrchestrator.RunAsync"/>, and updates
/// progress + buttons as the scan proceeds.
/// </summary>
[SupportedOSPlatform("windows")]
internal static class GuiHost
{
    public static int Run(ScanOptions opts)
    {
        ApplicationConfiguration.Initialize();

        using var form = new MainForm(Program.Version);
        ConsoleUI.Sink = new GuiUiSink(form);

        // Each click on "Start scan" launches a fresh background scan.
        form.StartRequested += async (_, __) =>
        {
            using var cts = new CancellationTokenSource();
            form.NotifyScanStarted(cts);

            var progress = new GuiProgressSink(form);
            try
            {
                var report = await Task.Run(() => ScanOrchestrator.RunAsync(opts, progress, cts.Token));

                string? htmlPath = null;
                if (!opts.NoHtml)
                {
                    try
                    {
                        htmlPath = HtmlReportRenderer.RenderToFile(report, opts.HtmlPathArg);
                        ConsoleUI.Ok($"HTML report saved: {htmlPath}");
                    }
                    catch (Exception ex)
                    {
                        ConsoleUI.Error($"Could not write HTML report: {ex.Message}");
                    }
                }

                form.NotifyScanFinished(cancelled: false, htmlPath: htmlPath);

                // Auto-open the HTML report on first finish, like the console did.
                if (htmlPath != null)
                {
                    try { HtmlReportRenderer.OpenInBrowser(htmlPath); }
                    catch { /* user can use the button */ }
                }
            }
            catch (OperationCanceledException)
            {
                form.NotifyScanFinished(cancelled: true, htmlPath: null);
            }
            catch (Exception ex)
            {
                form.NotifyScanFailed(ex.Message);
                ConsoleUI.Error($"Fatal: {ex.GetType().Name}: {ex.Message}");
            }
        };

        Application.Run(form);
        return 0;
    }

    private sealed class GuiProgressSink : IProgressSink
    {
        private readonly MainForm _form;
        public GuiProgressSink(MainForm form) { _form = form; }

        public void Begin(int totalSteps)
            => _form.SetProgress(0, totalSteps, "Starting…");

        public void StepStarted(string title, int index, int totalSteps)
            => _form.SetProgress(index - 1, totalSteps, title);

        public void StepFinished(string title, int index, int totalSteps)
            => _form.SetProgress(index, totalSteps, title);

        public void Finished()
            => _form.SetStatus("Wrapping up…");
    }
}
