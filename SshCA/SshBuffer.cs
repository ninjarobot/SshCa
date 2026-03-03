/*
The MIT License (MIT)
Copyright © 2025-2026 Dave Curylo

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
documentation files (the "Software"), to deal in the Software without restriction, including without limitation the
rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit
persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the
Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
using System;
using System.Buffers.Binary;
using System.IO;
using System.Text;

namespace SshCA;

/// <summary>
/// Provides read and write operations for SSH wire-format data buffers,
/// using big-endian byte order as required by the OpenSSH protocol.
/// </summary>
public class SshBuffer
{
    private readonly Stream _stream;

    /// <summary>Initializes a new <see cref="SshBuffer"/> wrapping the given stream.</summary>
    public SshBuffer(Stream stream) => _stream = stream;

    /// <summary>
    /// Reads the next string of bytes from the buffer, first by reading 4 bytes to get
    /// a 32-bit integer length, then reading that length of data.
    /// </summary>
    public byte[] ReadSshData()
    {
        byte[] sizeBuf = new byte[4];
        _stream.ReadExactly(sizeBuf);
        uint len = BinaryPrimitives.ReadUInt32BigEndian(sizeBuf);
        byte[] data = new byte[(int)len];
        _stream.ReadExactly(data);
        return data;
    }

    /// <summary>
    /// Writes the string of bytes to the buffer, first by writing the length as a 32-bit integer
    /// followed by the bytes themselves.
    /// </summary>
    public void WriteSshData(byte[] bytes)
    {
        // Openssh processes these in big endian due to the network libraries used.
        byte[] sizeBuf = new byte[4];
        BinaryPrimitives.WriteInt32BigEndian(sizeBuf, bytes.Length);
        _stream.Write(sizeBuf);
        _stream.Write(bytes);
    }

    /// <summary>
    /// Writes a string to the SSH buffer after converting it to UTF-8.
    /// This function ensures compatibility with OpenSSH's use of big-endian network byte order.
    /// </summary>
    public void WriteSshString(string value)
    {
        if (value is null)
            WriteSshData(Array.Empty<byte>());
        else
            WriteSshData(Encoding.UTF8.GetBytes(value));
    }

    /// <summary>
    /// Writes the given int64 value directly to the SSH buffer in big-endian format.
    /// This function ensures compatibility with OpenSSH's use of big-endian network byte order.
    /// </summary>
    public void WriteSshData(long value)
    {
        // OpenSSH processes them in big endian due to the network libraries used.
        byte[] buf = new byte[sizeof(long)];
        BinaryPrimitives.WriteInt64BigEndian(buf, value);
        _stream.Write(buf);
    }

    /// <summary>Writes the given uint64 value directly to the SSH buffer in big-endian format.</summary>
    public void WriteSshData(ulong value)
    {
        byte[] buf = new byte[sizeof(ulong)];
        BinaryPrimitives.WriteUInt64BigEndian(buf, value);
        _stream.Write(buf);
    }

    /// <summary>Writes the given uint32 value directly to the SSH buffer in big-endian format.</summary>
    public void WriteSshData(uint value)
    {
        byte[] buf = new byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32BigEndian(buf, value);
        _stream.Write(buf);
    }

    /// <summary>Directly writes bytes to the SSH buffer.</summary>
    public void WriteSshRaw(byte[] bytes) => _stream.Write(bytes);
}
