(*
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
*)
module SshBufferTests

open System
open System.Text
open Expecto
open System.IO
open System.Buffers.Binary
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
        
        testList "Buffer Truncation Validation" [
            test "ReadSshData with truncated data throws" {
                use ms = new MemoryStream()
                let sshBuf = SshBuffer(ms)
                
                // Write length = 100, but only provide 5 bytes of data
                let declaredLength = 100u
                let lengthBytes = [| 0uy; 0uy; 0uy; 0uy |]
                BinaryPrimitives.WriteUInt32BigEndian(lengthBytes, declaredLength)
                ms.Write(lengthBytes)
                ms.Write([| 1uy; 2uy; 3uy; 4uy; 5uy |]) // Only 5 bytes, not 100
                ms.Position <- 0L
                
                Expect.throws
                    (fun () -> sshBuf.ReadSshData() |> ignore)
                    "Should throw when stream has less data than length field declares"
            }
            
            test "ReadSshData with zero-length data returns empty array" {
                use ms = new MemoryStream()
                let sshBuf = SshBuffer(ms)
                
                // Write length = 0
                let lengthBytes = [| 0uy; 0uy; 0uy; 0uy |]
                ms.Write(lengthBytes)
                ms.Position <- 0L
                
                let result = sshBuf.ReadSshData()
                
                Expect.equal result.Length 0 "Zero-length data should return empty array"
            }
            
            test "ReadSshData with empty stream throws" {
                use ms = new MemoryStream()
                let sshBuf = SshBuffer(ms)
                
                Expect.throws
                    (fun () -> sshBuf.ReadSshData() |> ignore)
                    "Should throw when reading from empty stream"
            }
            
            test "ReadSshData with only length field (no data) throws" {
                use ms = new MemoryStream()
                let sshBuf = SshBuffer(ms)
                
                // Write length = 10 but provide no data
                let lengthBytes = [| 0uy; 0uy; 0uy; 10uy |]
                ms.Write(lengthBytes)
                ms.Position <- 0L
                
                Expect.throws
                    (fun () -> sshBuf.ReadSshData() |> ignore)
                    "Should throw when stream truncated after length field"
            }
            
            test "ReadSshData with partial length field throws" {
                use ms = new MemoryStream()
                let sshBuf = SshBuffer(ms)
                
                // Write only 3 bytes of length field (need 4)
                ms.Write([| 0uy; 0uy; 0uy |])
                ms.Position <- 0L
                
                Expect.throws
                    (fun () -> sshBuf.ReadSshData() |> ignore)
                    "Should throw when length field is incomplete"
            }
        ]
        
        testList "Integer Overflow Protection" [
            test "ReadSshData with length > Int32.MaxValue throws" {
                use ms = new MemoryStream()
                let sshBuf = SshBuffer(ms)
                
                // Write a length > Int32.MaxValue (0x80000000 = 2,147,483,648)
                let maliciousLength = 0x80000000u
                let lengthBytes = [| 0uy; 0uy; 0uy; 0uy |]
                BinaryPrimitives.WriteUInt32BigEndian(lengthBytes, maliciousLength)
                ms.Write(lengthBytes)
                ms.Position <- 0L
                
                Expect.throws
                    (fun () -> sshBuf.ReadSshData() |> ignore)
                    "Should reject lengths > Int32.MaxValue"
            }
            
            test "ReadSshData with unreasonably large length throws" {
                use ms = new MemoryStream()
                let sshBuf = SshBuffer(ms)
                
                // Write length > 10MB (DoS protection)
                let hugeLength = 100_000_000u // 100MB
                let lengthBytes = [| 0uy; 0uy; 0uy; 0uy |]
                BinaryPrimitives.WriteUInt32BigEndian(lengthBytes, hugeLength)
                ms.Write(lengthBytes)
                ms.Position <- 0L
                
                Expect.throws
                    (fun () -> sshBuf.ReadSshData() |> ignore)
                    "Should reject unreasonably large lengths to prevent DoS"
            }
            
            test "ReadSshData with maximum uint32 throws" {
                use ms = new MemoryStream()
                let sshBuf = SshBuffer(ms)
                
                // Write the maximum possible uint32 value
                let maxLength = System.UInt32.MaxValue
                let lengthBytes = [| 0uy; 0uy; 0uy; 0uy |]
                BinaryPrimitives.WriteUInt32BigEndian(lengthBytes, maxLength)
                ms.Write(lengthBytes)
                ms.Position <- 0L
                
                Expect.throws
                    (fun () -> sshBuf.ReadSshData() |> ignore)
                    "Should reject UInt32.MaxValue to prevent overflow"
            }
        ]
    ]