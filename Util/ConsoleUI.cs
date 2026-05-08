namespace McSsCheck.Util;

/// <summary>
/// Static facade scanners use to print severity-tinted text. Internally
/// delegates to whatever <see cref="IUiSink"/> the host installed (console
/// in <c>--console</c> mode, GUI in default mode).
/// </summary>
internal static class ConsoleUI
{
    /// <summary>
    /// Active sink. Default = console output. The GUI host replaces this
    /// at startup before any scanner runs.
    /// </summary>
    public static IUiSink Sink { get; set; } = new ConsoleUiSink();

    public static void Banner(string title) => Sink.Banner(title);
    public static void Section(string title) => Sink.Section(title);
    public static void Info(string text)    => Sink.Info(text);
    public static void Ok(string text)      => Sink.Ok(text);
    public static void Warn(string text)    => Sink.Warn(text);
    public static void Hit(string text)     => Sink.Hit(text);
    public static void Error(string text)   => Sink.Error(text);
    public static void Dim(string text)     => Sink.Dim(text);
}
