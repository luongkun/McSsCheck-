using McSsCheck.Util;

namespace McSsCheck.Gui;

/// <summary>
/// <see cref="IUiSink"/> implementation that forwards to a
/// <see cref="MainForm"/>'s coloured log. Thread-safe — the form
/// marshals to the UI thread internally.
/// </summary>
internal sealed class GuiUiSink : IUiSink
{
    private readonly MainForm _form;
    public GuiUiSink(MainForm form) { _form = form; }

    public void Banner(string title)  => _form.AppendLine(title, MainForm.LineKind.Banner);
    public void Section(string title) => _form.AppendLine(title, MainForm.LineKind.Section);
    public void Info(string text)     => _form.AppendLine(text,  MainForm.LineKind.Info);
    public void Ok(string text)       => _form.AppendLine(text,  MainForm.LineKind.Ok);
    public void Warn(string text)     => _form.AppendLine(text,  MainForm.LineKind.Warn);
    public void Hit(string text)      => _form.AppendLine(text,  MainForm.LineKind.Hit);
    public void Error(string text)    => _form.AppendLine(text,  MainForm.LineKind.Error);
    public void Dim(string text)      => _form.AppendLine(text,  MainForm.LineKind.Dim);
}
