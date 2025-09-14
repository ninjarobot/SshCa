module SshBufferTests

open System
open System.Text
open Expecto
open System.IO
open SshCA

[<Tests>]
let tests =
    testList "SSH Buffer Tests" [
        test "Append buffer has correct size" {
            use ms = new MemoryStream()
            let testData = "some test data" |> Encoding.UTF8.GetBytes
            let dataLen = testData.Length
            let sshBuf = SshBuffer(ms)
            testData |> sshBuf.AppendSshBuf
            ms.Position <- 0 // Move to beginning so we can read what was put in it.
            let size = Array.zeroCreate<byte> 4
            ms.Read size |> ignore
            if BitConverter.IsLittleEndian then
                Array.Reverse size // stream should contain the value in big endian, so needs to be reversed.
            Expect.sequenceEqual
                size
                (BitConverter.GetBytes dataLen)
                "Incorrect size"
            let resultingData = Array.zeroCreate<byte> dataLen
            ms.Read resultingData |> ignore
            Expect.sequenceEqual
                resultingData
                testData
                "Incorrect data in stream"
        }
    ]