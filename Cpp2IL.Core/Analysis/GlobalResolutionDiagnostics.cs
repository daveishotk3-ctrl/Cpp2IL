using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using Cpp2IL.Core.Logging;
using LibCpp2IL;
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
    private const int MaxProbeSlots = 3000;

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
        var probeSlots = new List<(ulong Address, ulong Value)>(); // non-zero file-backed slots, most used first, for the structure probe below

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
                        if (probeSlots.Count < MaxProbeSlots)
                            probeSlots.Add((address, value));
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
        AppendPointerProbe(sb, appContext, probeSlots);
        sb.Append("  (Includes any ordinary static-data loads, not only metadata. Send this report along when asking for recovery fixes.)");

        // One summary line by default; the full breakdown (useful when a new Unity version stops resolving) only with --verbose.
        Logger.InfoNewline($"{Interlocked.Read(ref state.Resolved)} metadata references resolved; {unresolved.Length} distinct addresses left unresolved (mostly constants and init flags). Use --verbose for a detailed report.", "Globals");
        Logger.VerboseNewline(sb.ToString(), "Globals");
    }

    /// <summary>
    /// For slots that hold a non-zero value, checks whether the value looks like a pointer to a known IL2CPP structure
    /// (an Il2CppType, or something that embeds/points to one, or a MethodInfo-like struct starting with a method pointer),
    /// and at which offsets. This reveals the layout newer Unity versions use for their metadata globals.
    /// </summary>
    private static void AppendPointerProbe(StringBuilder sb, ApplicationAnalysisContext appContext, List<(ulong Address, ulong Value)> slots)
    {
        if (slots.Count == 0)
            return;

        var binary = appContext.Binary;
        var step = binary.is32Bit ? 4UL : 8UL;

        var methodPointers = new HashSet<ulong>();
        foreach (var assembly in appContext.Assemblies)
        foreach (var type in assembly.Types)
        foreach (var method in type.Methods)
        {
            var pointer = method.Definition?.MethodPointer ?? 0;
            if (pointer != 0)
                methodPointers.Add(pointer);
        }

        var limits = appContext.LibCpp2IlContext.GetUsageLimits();
        var indirectZero = 0;
        var indirectBadShape = 0; // not an odd 32-bit value, so it doesn't look like an encoded usage
        var indirectKinds = new SortedDictionary<int, long[]>();

        var valueIsType = 0;
        var valueIsMethod = 0;
        var valueBacked = 0;
        var typeAt = new SortedDictionary<ulong, int>(); // value + k is the address of a known Il2CppType (type embedded in the pointed-to struct)
        var typePtrAt = new SortedDictionary<ulong, int>(); // *(value + k) is the address of a known Il2CppType
        var methodPtrAt = new SortedDictionary<ulong, int>(); // *(value + k) is a known method pointer

        foreach (var slot in slots)
        {
            var value = slot.Value;

            if (binary.TryGetIl2CppTypeFromPointer(value, out _))
                valueIsType++;

            if (methodPointers.Contains(value))
                valueIsMethod++;

            if (!TryReadPointer(binary, value, out _))
                continue;

            valueBacked++;

            if (TryReadPointer(binary, value, out var indirect))
            {
                if (indirect == 0)
                    indirectZero++;
                else if ((indirect & 1) == 0 || (indirect >> 32) != 0)
                    indirectBadShape++;
                else
                {
                    var kind = (int)((indirect >> 29) & 7);
                    var index = (indirect & 0x1FFF_FFFF) >> 1;
                    var limit = kind switch { 1 or 2 => limits.Types, 3 => limits.Methods, 4 => limits.Fields, 5 => limits.Strings, 6 => limits.MethodSpecs, _ => -1L };

                    if (!indirectKinds.TryGetValue(kind, out var stat))
                        indirectKinds[kind] = stat = new long[] { 0, long.MaxValue, 0, 0 }; // count, min index, max index, over limit

                    stat[0]++;
                    stat[1] = Math.Min(stat[1], (long)index);
                    stat[2] = Math.Max(stat[2], (long)index);
                    if (limit >= 0 && (long)index >= limit)
                        stat[3]++;
                }
            }

            for (var k = 0UL; k <= 0x1F8; k += step)
                if (binary.TryGetIl2CppTypeFromPointer(value + k, out _))
                    Bump(typeAt, k);

            for (var k = 0UL; k <= 0xF8; k += step)
            {
                if (!TryReadPointer(binary, value + k, out var pointed))
                    continue;

                if (binary.TryGetIl2CppTypeFromPointer(pointed, out _))
                    Bump(typePtrAt, k);

                if (k <= 0x38 && methodPointers.Contains(pointed))
                    Bump(methodPtrAt, k);
            }
        }

        sb.AppendLine($"  Pointer probe over {slots.Count} non-zero slots ({valueBacked} point into file-backed memory):");
        sb.AppendLine($"    slot value is itself an Il2CppType*: {valueIsType}; is a method pointer: {valueIsMethod}");
        sb.AppendLine($"    indirect values (*slot): {indirectZero} zero, {indirectBadShape} not shaped like an encoded usage; limits: types {limits.Types}, methods {limits.Methods}, fields {limits.Fields}, strings {limits.Strings}, methodSpecs {limits.MethodSpecs}");
        foreach (var kind in indirectKinds)
            sb.AppendLine($"      kind {kind.Key}: {kind.Value[0]} values, index {kind.Value[1]}..{kind.Value[2]}, {kind.Value[3]} at/over limit");
        sb.AppendLine($"    Il2CppType embedded at +offset: {Top(typeAt)}");
        sb.AppendLine($"    Il2CppType* stored at +offset: {Top(typePtrAt)}");
        sb.AppendLine($"    method pointer stored at +offset: {Top(methodPtrAt)}");

        foreach (var slot in slots.Take(3))
        {
            var words = new List<string>();
            for (var i = 0UL; i < 8; i++)
                words.Add(TryReadPointer(binary, slot.Value + i * step, out var word) ? $"{word:X}" : "?");

            sb.AppendLine($"    target of 0x{slot.Address:X} (0x{slot.Value:X}): {string.Join(" ", words)}");
        }
    }

    private static bool TryReadPointer(Il2CppBinary binary, ulong address, out ulong value)
    {
        value = 0;

        try
        {
            if (!binary.TryMapVirtualAddressToRaw(address, out var raw) || raw >= binary.RawLength)
                return false;

            value = binary.ReadPointerAtVirtualAddress(address);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static void Bump(SortedDictionary<ulong, int> counts, ulong key)
    {
        counts.TryGetValue(key, out var previous);
        counts[key] = previous + 1;
    }

    private static string Top(SortedDictionary<ulong, int> counts)
        => counts.Count == 0
            ? "none"
            : string.Join(", ", counts.OrderByDescending(kvp => kvp.Value).Take(4).Select(kvp => $"+0x{kvp.Key:X}:{kvp.Value}"));
}
