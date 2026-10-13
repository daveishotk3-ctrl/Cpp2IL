using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using Cpp2IL.Core.Logging;
using Cpp2IL.Core.Model.Contexts;

namespace Cpp2IL.Core.Analysis;

/// <summary>
/// Collects statistics about absolute-address loads that could not be resolved to IL2CPP metadata (string literals, types, methods, fields),
/// and prints a short report describing why. Newer Unity versions have changed how these metadata "globals" are stored a few times, and when
/// resolution fails the decompiled output degrades into placeholder values, so this report makes the cause visible.
/// Collection is opt-in per application context (see <see cref="Enable"/>) and costs nothing when not enabled.
/// </summary>
public static class GlobalResolutionDiagnostics
{
    private const string StorageKey = "Cpp2IL.GlobalResolutionDiagnostics";
    private const int MaxSamples = 8;

    private sealed class State
    {
        public long Resolved;
        public readonly ConcurrentDictionary<ulong, int> UnresolvedHits = new();
    }

    /// <summary>Starts collecting. Must be called before (not during) parallel analysis.</summary>
    public static void Enable(ApplicationAnalysisContext appContext) => appContext.PutExtraData(StorageKey, new State());

    internal static void RecordResolved(ApplicationAnalysisContext appContext)
    {
        if (appContext.GetExtraData<State>(StorageKey) is { } state)
            Interlocked.Increment(ref state.Resolved);
    }

    internal static void RecordUnresolved(ApplicationAnalysisContext appContext, ulong address)
    {
        if (appContext.GetExtraData<State>(StorageKey) is { } state)
            state.UnresolvedHits.AddOrUpdate(address, 1, static (_, count) => count + 1);
    }

    /// <summary>Logs the report. Does nothing if collection was never enabled.</summary>
    public static void Report(ApplicationAnalysisContext appContext)
    {
        if (appContext.GetExtraData<State>(StorageKey) is not { } state)
            return;

        var binary = appContext.Binary;
        var unresolved = state.UnresolvedHits.ToArray();
        var totalHits = unresolved.Sum(kvp => (long)kvp.Value);

        var unbacked = 0; // address has no bytes in the file (e.g. zero-initialised memory), so nothing can be read statically
        var zero = 0; // readable but zero
        var nonZero = 0; // readable and non-zero
        var topBits = new SortedDictionary<ulong, int>(); // histogram of the top 3 bits of non-zero values (where the legacy encoding keeps the usage kind)
        var samples = new List<(ulong Address, int Hits, string Description)>();

        foreach (var entry in unresolved.OrderByDescending(kvp => kvp.Value))
        {
            var address = entry.Key;
            var hits = entry.Value;
            string description;
            try
            {
                if (!binary.TryMapVirtualAddressToRaw(address, out var raw) || raw >= binary.RawLength)
                {
                    unbacked++;
                    description = "no file backing";
                }
                else
                {
                    var value = binary.ReadPointerAtVirtualAddress(address);
                    if (value == 0)
                    {
                        zero++;
                        description = "0";
                    }
                    else
                    {
                        nonZero++;
                        var bits = (value >> 29) & 7;
                        topBits.TryGetValue(bits, out var previous);
                        topBits[bits] = previous + 1;
                        description = $"0x{value:X} (top3bits={bits}, low29={value & 0x1FFF_FFFF})";
                    }
                }
            }
            catch (Exception e)
            {
                unbacked++;
                description = "unreadable: " + e.GetType().Name;
            }

            if (samples.Count < MaxSamples)
                samples.Add((address, hits, description));
        }

        var sb = new StringBuilder();
        sb.AppendLine($"Global resolution report (metadata v{appContext.MetadataVersion}, Unity {appContext.UnityVersion}):");
        sb.AppendLine($"  {Interlocked.Read(ref state.Resolved)} absolute loads resolved to metadata (strings/types/methods/fields)");
        sb.AppendLine($"  {unresolved.Length} distinct addresses unresolved ({totalHits} loads):");
        sb.AppendLine($"    {unbacked} have no file backing (zero-initialised memory - values cannot be read statically)");
        sb.AppendLine($"    {zero} are readable but zero");
        sb.AppendLine($"    {nonZero} are readable and non-zero" + (topBits.Count > 0 ? $" - top-3-bit histogram: {string.Join(", ", topBits.Select(kvp => $"{kvp.Key}:{kvp.Value}"))}" : ""));
        foreach (var sample in samples)
            sb.AppendLine($"    e.g. 0x{sample.Address:X} used {sample.Hits}x, file value: {sample.Description}");
        sb.Append("  (Includes any ordinary static-data loads, not only metadata. Send this report along when asking for recovery fixes.)");

        Logger.InfoNewline(sb.ToString(), "Globals");
    }
}
