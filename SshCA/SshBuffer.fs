namespace SshCA

open System.Buffers.Binary
open System.IO
open System.Text

type SshBuffer(stream:Stream) =
    /// Reads the next string of bytes from the buffer, first by reading 4 bytes to get
    /// a 32-bit integer length, then reading that length of data.
    member _.ReadSshData () =
        let sizeBuf : byte array = Array.zeroCreate 4
        stream.ReadExactly(sizeBuf)
        let len = BinaryPrimitives.ReadUInt32BigEndian sizeBuf
        let data : byte array = Array.zeroCreate (len |> int)
        stream.ReadExactly data
        data

    /// Writes the string of bytes to the buffer, first by writing the length as a 32-bit integer
    /// followed by the bytes themselves.
    member _.WriteSshData (bytes: byte array)=
        // Openssh processes these in big endian due to the network libraries used.
        let sizeBuf = Array.zeroCreate<byte> 4
        BinaryPrimitives.WriteInt32BigEndian(sizeBuf, bytes.Length)
        stream.Write sizeBuf
        stream.Write bytes

    /// Writes a string to the SSH buffer after converting it to UTF-8.
    ///
    /// This function ensures compatibility with OpenSSH's use of big-endian network byte order.
    member this.WriteSshString (value:string) =
        if isNull value then
            [||] |> this.WriteSshData
        else
            value |> (Encoding.UTF8.GetBytes >> this.WriteSshData)
    /// Writes the given value to the SSH buffer. The value can be of various types, including
    /// byte array, string, int64, uint64, or uint32. The buffer first encodes the length of the value
    /// as a 32-bit integer (if applicable) and writes it in big-endian format, followed by the
    /// serialized data itself.
    ///
    /// This function ensures compatibility with OpenSSH's use of big-endian network byte order.
    member _.WriteSshData (value:int64)=
        // OpenSSH processes them in big endian due to the network libraries used.
        let buf = Array.zeroCreate<byte>(sizeof<int64>)
        BinaryPrimitives.WriteInt64BigEndian(buf, value)
        stream.Write buf
    member _.WriteSshData (value:uint64)=
        let buf = Array.zeroCreate<byte>(sizeof<uint64>)
        BinaryPrimitives.WriteUInt64BigEndian(buf, value)
        stream.Write buf
    member _.WriteSshData (value:uint32)=
        let buf = Array.zeroCreate<byte>(sizeof<uint32>)
        BinaryPrimitives.WriteUInt32BigEndian(buf, value)
        stream.Write buf
    /// Directly writes bytes to the SSH buffer.
    member _.WriteSshRaw (bytes:byte array)= stream.Write bytes
