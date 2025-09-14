namespace SshCA

open System
open System.IO

module SshBuffer =

    module Array =
        /// Reverses an array when running on a Little Endian architecture.
        /// For efficiency, this does not return a new array like `Array.rev` would.
        let revIfLittleEndian arr =
            if BitConverter.IsLittleEndian then
                Array.Reverse arr
            arr

    /// Reads the next string of bytes from the buffer, first by reading 4 bytes to get
    /// a 32-bit integer length, then reading that length of data.
    let readSshBuf (ms: Stream) =
        let size : byte array = Array.zeroCreate 4
        ms.Read(size) |> ignore
        if BitConverter.IsLittleEndian then
            Array.Reverse size // reverse the array since it is a little endian architecture
        let len = size |> BitConverter.ToUInt32
        let data : byte array = Array.zeroCreate (len |> int)
        ms.Read data |> ignore
        data

    /// Writes the string of bytes to the buffer, first by writing the length as a 32-bit integer
    /// followed by the bytes themselves.
    let appendSshBuf (ms:Stream) (bytes: byte array)=
        let size = bytes.Length |> BitConverter.GetBytes
        // If running a little endian system, BitConverter converts the numbers in little endian
        // order, but openssh processes them in big endian due to the network libraries used.
        size |> Array.revIfLittleEndian |> ms.Write
        ms.Write bytes
