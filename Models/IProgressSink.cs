namespace McSsCheck.Models;

/// <summary>
/// Lets a host (console / GUI) observe scan progress without coupling to
/// the orchestrator's internals. Implementations must be thread-safe — calls
/// happen from a background thread.
/// </summary>
internal interface IProgressSink
{
    /// <summary>Called once before any step. <paramref name="totalSteps"/> is the count of enabled scanners.</summary>
    void Begin(int totalSteps);

    /// <summary>Called when a section starts. <paramref name="index"/> is 1-based.</summary>
    void StepStarted(string title, int index, int totalSteps);

    /// <summary>Called when a section finishes (regardless of success/failure).</summary>
    void StepFinished(string title, int index, int totalSteps);

    /// <summary>Called once after all sections — even on cancellation.</summary>
    void Finished();
}

/// <summary>
/// Null implementation. The console host uses this because progress is
/// already implicit in the streaming output.
/// </summary>
internal sealed class NullProgressSink : IProgressSink
{
    public static readonly NullProgressSink Instance = new();
    public void Begin(int totalSteps) { }
    public void StepStarted(string title, int index, int totalSteps) { }
    public void StepFinished(string title, int index, int totalSteps) { }
    public void Finished() { }
}
