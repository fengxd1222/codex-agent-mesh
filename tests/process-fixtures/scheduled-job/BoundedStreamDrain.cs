using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

public sealed class BoundedStreamDrain {
    readonly Stream stream;
    readonly int totalLimit;
    readonly int lineLimit;
    readonly MemoryStream retained;
    readonly Task pump;
    long observedBytes;
    int currentLineBytes;
    int maximumLineBytes;
    bool truncated;

    BoundedStreamDrain(Stream stream, int totalLimit, int lineLimit) {
        if (stream == null) throw new ArgumentNullException("stream");
        if (totalLimit <= 0 || lineLimit <= 0 || lineLimit > totalLimit) throw new ArgumentOutOfRangeException("limit");
        this.stream = stream;
        this.totalLimit = totalLimit;
        this.lineLimit = lineLimit;
        retained = new MemoryStream(Math.Min(totalLimit, 8192));
        pump = Task.Run((Action)Pump);
    }

    public static BoundedStreamDrain Start(Stream stream, int totalLimit, int lineLimit) {
        return new BoundedStreamDrain(stream, totalLimit, lineLimit);
    }

    void Pump() {
        var buffer = new byte[4096];
        for (;;) {
            int count = stream.Read(buffer, 0, buffer.Length);
            if (count == 0) return;
            observedBytes = observedBytes > long.MaxValue - count ? long.MaxValue : observedBytes + count;
            for (int index = 0; index < count; index++) {
                byte value = buffer[index];
                if (value == (byte)'\n') {
                    currentLineBytes = 0;
                    if (retained.Length < totalLimit) retained.WriteByte(value); else truncated = true;
                    continue;
                }
                currentLineBytes = currentLineBytes == int.MaxValue ? int.MaxValue : currentLineBytes + 1;
                if (currentLineBytes > maximumLineBytes) maximumLineBytes = currentLineBytes;
                if (currentLineBytes <= lineLimit && retained.Length < totalLimit) retained.WriteByte(value); else truncated = true;
            }
        }
    }

    public bool WaitForCompletion(int timeoutMilliseconds) {
        if (timeoutMilliseconds < 0) throw new ArgumentOutOfRangeException("timeoutMilliseconds");
        try { return pump.Wait(timeoutMilliseconds); }
        catch (AggregateException) { throw new InvalidOperationException("bounded stream drain failed"); }
    }

    public long ObservedBytes { get { EnsureCompleted(); return observedBytes; } }
    public int RetainedBytes { get { EnsureCompleted(); return checked((int)retained.Length); } }
    public int MaximumLineBytes { get { EnsureCompleted(); return maximumLineBytes; } }
    public bool Truncated { get { EnsureCompleted(); return truncated; } }

    public string CapturedUtf8Text() {
        EnsureCompleted();
        return new UTF8Encoding(false, true).GetString(retained.ToArray());
    }

    public string CapturedSha256Hex() {
        EnsureCompleted();
        using (var sha = SHA256.Create()) {
            return BitConverter.ToString(sha.ComputeHash(retained.ToArray())).Replace("-", "").ToLowerInvariant();
        }
    }

    void EnsureCompleted() {
        if (!pump.IsCompleted) throw new InvalidOperationException("bounded stream drain is still active");
        if (pump.IsFaulted) throw new InvalidOperationException("bounded stream drain failed");
    }
}
