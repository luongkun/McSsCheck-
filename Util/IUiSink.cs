namespace McSsCheck.Util;

/// <summary>
/// Severity-tinted output abstraction used by every scanner via
/// <see cref="ConsoleUI"/>. Default implementation writes to the OS console
/// (<see cref="ConsoleUiSink"/>); the GUI host swaps in
/// <see cref="McSsCheck.Gui.GuiUiSink"/> at startup so the same calls land
/// in the WinForms log instead.
///
/// Implementations MUST be thread-safe — scanners call into this concurrently
/// and from background threads.
/// </summary>
internal interface IUiSink
{
    void Banner(string title);
    void Section(string title);
    void Info(string text);
    void Ok(string text);
    void Warn(string text);
    void Hit(string text);
    void Error(string text);
    void Dim(string text);
}
