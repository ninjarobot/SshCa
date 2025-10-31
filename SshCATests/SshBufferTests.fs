(*
The MIT License (MIT)
Copyright © 2025 Dave Curylo

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
*)
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
            testData |> sshBuf.WriteSshData
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