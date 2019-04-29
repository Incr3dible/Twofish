using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Twofish
{
    [DebuggerDisplay("{" + nameof(Value) + "}")]
    [StructLayout(LayoutKind.Explicit)]
    public struct DWord
    {
        [FieldOffset(0)] public byte B0;
        [FieldOffset(1)] public byte B1;
        [FieldOffset(2)] public byte B2;
        [FieldOffset(3)] public byte B3;

        [FieldOffset(0)] private uint Value;

        public DWord(uint value) : this()
        {
            Value = value;
        }

        public DWord(IReadOnlyList<byte> buffer, int offset) : this()
        {
            B0 = buffer[offset];
            B1 = buffer[offset + 1];
            B2 = buffer[offset + 2];
            B3 = buffer[offset + 3];
        }

        public static explicit operator uint(DWord expr) => expr.Value;

        public static explicit operator DWord(int value) => new DWord((uint) value);

        public static explicit operator DWord(uint value) => new DWord(value);

        public static DWord operator +(DWord expr1, DWord expr2)
        {
            expr1.Value += expr2.Value;
            return expr1;
        }

        public static DWord operator *(uint value, DWord expr)
        {
            expr.Value = value * expr.Value;
            return expr;
        }

        public static DWord operator |(DWord expr1, DWord expr2)
        {
            expr1.Value |= expr2.Value;
            return expr1;
        }

        public static DWord operator ^(DWord expr1, DWord expr2)
        {
            expr1.Value ^= expr2.Value;
            return expr1;
        }

        public static DWord operator <<(DWord expr, int count)
        {
            expr.Value <<= count;
            return expr;
        }

        public static DWord operator >>(DWord expr, int count)
        {
            expr.Value >>= count;
            return expr;
        }
    }
}