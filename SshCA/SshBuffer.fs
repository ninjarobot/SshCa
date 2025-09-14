namespace SshCA

open System
open System.IO
open System.Text

module Array =
    /// Reverses an array when running on a Little Endian architecture.
    /// For efficiency, this does not return a new array like `Array.rev` would.
    let revIfLittleEndian arr =
        if BitConverter.IsLittleEndian then
            Array.Reverse arr
        arr

type SshBuffer(stream:Stream) =

    /// Reads the next string of bytes from the buffer, first by reading 4 bytes to get
    /// a 32-bit integer length, then reading that length of data.
    member _.ReadSshBuf () =
        let size : byte array = Array.zeroCreate 4
        stream.Read(size) |> ignore
        if BitConverter.IsLittleEndian then
            Array.Reverse size // reverse the array since it is a little endian architecture
        let len = size |> BitConverter.ToUInt32
        let data : byte array = Array.zeroCreate (len |> int)
        stream.Read data |> ignore
        data

    /// Writes the string of bytes to the buffer, first by writing the length as a 32-bit integer
    /// followed by the bytes themselves.
    member _.AppendSshBuf (bytes: byte array)=
        let size = bytes.Length |> BitConverter.GetBytes
        // If running a little endian system, BitConverter converts the numbers in little endian
        // order, but openssh processes them in big endian due to the network libraries used.
        size |> Array.revIfLittleEndian |> stream.Write
        stream.Write bytes

    /// Writes the given value to the SSH buffer. The value can be of various types, including
    /// byte array, string, int64, uint64, or uint32. The buffer first encodes the length of the value
    /// as a 32-bit integer (if applicable) and writes it in big-endian format, followed by the
    /// serialized data itself.
    ///
    /// This function ensures compatibility with OpenSSH's use of big-endian network byte order.
    member this.AppendSshBuf (value:string) =
        value |> (Encoding.UTF8.GetBytes >> this.AppendSshBuf)
    member _.AppendSshBuf (value:int64)=
        let bytes = value |> BitConverter.GetBytes
        // If running a little endian system, BitConverter converts the numbers in little endian
        // order, but openssh processes them in big endian due to the network libraries used.
        bytes |> Array.revIfLittleEndian |> stream.Write
    member _.AppendSshBuf (value:uint64)=
        let bytes = value |> BitConverter.GetBytes
        // If running a little endian system, BitConverter converts the numbers in little endian
        // order, but openssh processes them in big endian due to the network libraries used.
        bytes |> Array.revIfLittleEndian |> stream.Write
    member _.AppendSshBuf (value:uint32)=
        let bytes = value |> BitConverter.GetBytes
        // If running a little endian system, BitConverter converts the numbers in little endian
        // order, but openssh processes them in big endian due to the network libraries used.
        bytes |> Array.revIfLittleEndian |> stream.Write
    member _.AppendSshBufRaw (bytes:byte array)= stream.Write bytes
