using System;
using System.IO;
using System.Text;

namespace SshCA
{
    public class SshBuffer
    {
        private readonly Stream _stream;

        public SshBuffer(Stream stream)
        {
            _stream = stream ?? throw new ArgumentNullException(nameof(stream));
        }

        public byte[] ReadSshBuf()
        {
            var size = new byte[4];
            _ = _stream.Read(size, 0, size.Length);
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(size);
            }

            var len = BitConverter.ToUInt32(size, 0);
            var data = new byte[len];
            _ = _stream.Read(data, 0, (int)len);
            return data;
        }

        private static void RevIfLittleEndian(Span<byte> span)
        {
            if (BitConverter.IsLittleEndian)
            {
                span.Reverse();
            }
        }

        public void AppendSshBuf(byte[] bytes)
        {
            if (bytes is null) throw new ArgumentNullException(nameof(bytes));
            var size = BitConverter.GetBytes(bytes.Length);
            RevIfLittleEndian(size.AsSpan());
            _stream.Write(size, 0, size.Length);
            _stream.Write(bytes, 0, bytes.Length);
        }

        public void AppendSshBuf(string value)
        {
            if (value is null) throw new ArgumentNullException(nameof(value));
            AppendSshBuf(Encoding.UTF8.GetBytes(value));
        }

        public void AppendSshBuf(long value)
        {
            var bytes = BitConverter.GetBytes(value);
            RevIfLittleEndian(bytes.AsSpan());
            _stream.Write(bytes, 0, bytes.Length);
        }

        public void AppendSshBuf(ulong value)
        {
            var bytes = BitConverter.GetBytes(value);
            RevIfLittleEndian(bytes.AsSpan());
            _stream.Write(bytes, 0, bytes.Length);
        }

        public void AppendSshBuf(uint value)
        {
            var bytes = BitConverter.GetBytes(value);
            RevIfLittleEndian(bytes.AsSpan());
            _stream.Write(bytes, 0, bytes.Length);
        }

        public void AppendSshBufRaw(byte[] bytes)
        {
            if (bytes is null) throw new ArgumentNullException(nameof(bytes));
            _stream.Write(bytes, 0, bytes.Length);
        }
    }
}
