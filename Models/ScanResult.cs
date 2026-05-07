using System;
using System.Collections.Generic;

namespace McSsCheck.Models;

public enum Severity { Info, Ok, Warn, Hit, Error }

public sealed record ScanResult(
    string Source,        // e.g. "ProcessScanner"
    Severity Severity,
    string Title,         // single-line summary
    string? Detail = null,// multi-line or longer description
    string? FilePath = null,
    string? Hash = null,
    DateTime? Timestamp = null,
    IReadOnlyList<string>? Tags = null
);
