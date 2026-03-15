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
module SshCertTests

open System
open System.IO
open System.Security.Cryptography
open Expecto
open Fli
open SshCA

[<Tests>]
let tests =
    testList "SSH Certificate Tests" [
        test "End to end with ssh-keygen validation" {
            use ca = RSA.Create()
            let caPubKey = ca.ExportRSAPublicKeyPem() |> PublicKey.OfRsaPublicKeyPem
            let pubKeyToSign = TestData.testSshKey |> PublicKey.OfSshPublicKey
            let certInfo =
                CertificateInfo("testkey", pubKeyToSign, caPubKey,
                                TestData.nonce,
                                Serial=0UL, Principals=["someUser"],
                                ValidAfter=DateTimeOffset(DateTime(2025, 6, 13, 8, 0, 0)),
                                ValidBefore=DateTimeOffset(DateTime(2025, 6, 13, 8, 0, 0)).AddHours 2
                )
            let certAuth = CertificateAuthority(fun ms -> ca.SignData(ms, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1))
            let certLine = certAuth.SignAndSerialize(certInfo, "testkey@domain")
            let tempFile = Path.GetTempFileName()
            File.WriteAllText(tempFile, certLine)
            let cmdResult =
                cli {
                    Exec "/usr/bin/ssh-keygen"
                    Arguments $"-L -f {tempFile}"
                } |> Command.execute
            let output = cmdResult |> Output.throwIfErrored |> Output.toText
            let out = new StringReader(output)
            out.ReadLine() |> ignore // Ignore tmp file name
            Expect.equal
                (out.ReadLine().Trim())
                "Type: ssh-rsa-cert-v01@openssh.com user certificate"
                "Certification validation type incorrect"
            out.ReadLine() |> ignore // Ignore Public key since it will change on each run
            out.ReadLine() |> ignore // Ignore Signing CA since it will change on each run
            Expect.equal
                (out.ReadLine().Trim())
                "Key ID: \"testkey\""
                "Certification validation Key ID incorrect"
            Expect.equal
                (out.ReadLine().Trim())
                "Serial: 0"
                "Certification validation serial incorrect"
            Expect.equal
                (out.ReadLine().Trim())
                "Valid: from 2025-06-13T08:00:00 to 2025-06-13T10:00:00"
                "Certification validation after and before incorrect"
            Expect.equal
                (out.ReadLine().Trim())
                "Principals:"
                "Certification validation missing Principals"
            Expect.equal
                (out.ReadLine().Trim())
                "someUser"
                "Certification validation missing 'someUser' principal"
            Expect.equal
                (out.ReadLine().Trim())
                "Critical Options: (none)"
                "Certification validation critical options incorrect"
            Expect.equal
                (out.ReadLine().Trim())
                "Extensions: (none)"
                "Certification validation extensions incorrect"
        }
        testTask "CA with async signing function" {
            let ca = RSA.Create()
            let caPubKey = ca.ExportRSAPublicKeyPem() |> PublicKey.OfRsaPublicKeyPem
            let pubKeyToSign = TestData.testSshKey |> PublicKey.OfSshPublicKey
            let certInfo =
                CertificateInfo("testkey", pubKeyToSign, caPubKey,
                                TestData.nonce,
                                Serial=0UL, Principals=["someUser"],
                                ValidAfter=DateTimeOffset(DateTime(2025, 6, 13, 8, 0, 0)),
                                ValidBefore=DateTimeOffset(DateTime(2025, 6, 13, 8, 0, 0)).AddHours 2
                )
            let asyncSigner =
                fun (stream:Stream) (_:System.Threading.CancellationToken) ->
                    backgroundTask {
                        return ca.SignData(stream, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1)
                    }
            let certAuth = CertificateAuthorityAsync(asyncSigner)
            let! (certLine:string) = certAuth.SignAndSerializeAsync(certInfo, "testkey@domain")
            let tempFile = Path.GetTempFileName()
            File.WriteAllText(tempFile, certLine)
            let cmdResult =
                cli {
                    Exec "/usr/bin/ssh-keygen"
                    Arguments $"-L -f {tempFile}"
                } |> Command.execute
            cmdResult |> Output.throwIfErrored |> ignore
        }
    ]

[<Tests>]
let certificateInfoTests =
    testList "CertificateInfo Tests" [
        test "Constructor with auto-generated nonce creates 32-byte nonce" {
            use ca = RSA.Create()
            let caPubKey = ca.ExportRSAPublicKeyPem() |> PublicKey.OfRsaPublicKeyPem
            let pubKeyToSign = TestData.testSshKey |> PublicKey.OfSshPublicKey
            
            let certInfo = CertificateInfo("testkey", pubKeyToSign, caPubKey)
            
            Expect.equal certInfo.Nonce.Length 32 "Nonce should be 32 bytes"
            Expect.notEqual certInfo.Nonce (Array.zeroCreate<byte> 32) "Nonce should not be all zeros"
        }

        test "Constructor with explicit nonce uses provided nonce" {
            use ca = RSA.Create()
            let caPubKey = ca.ExportRSAPublicKeyPem() |> PublicKey.OfRsaPublicKeyPem
            let pubKeyToSign = TestData.testSshKey |> PublicKey.OfSshPublicKey
            let customNonce = Array.create 32 42uy
            
            let certInfo = CertificateInfo("testkey", pubKeyToSign, caPubKey, customNonce)
            
            Expect.equal certInfo.Nonce customNonce "Nonce should match provided value"
        }

        test "Multiple principals are preserved" {
            use ca = RSA.Create()
            let caPubKey = ca.ExportRSAPublicKeyPem() |> PublicKey.OfRsaPublicKeyPem
            let pubKeyToSign = TestData.testSshKey |> PublicKey.OfSshPublicKey
            
            let certInfo = CertificateInfo("testkey", pubKeyToSign, caPubKey, TestData.nonce)
            certInfo.Principals <- ["user1"; "user2"; "user3"]
            
            let principals = certInfo.Principals |> Seq.toList
            Expect.equal principals.Length 3 "Should have 3 principals"
            Expect.equal principals.[0] "user1" "First principal incorrect"
            Expect.equal principals.[1] "user2" "Second principal incorrect"
            Expect.equal principals.[2] "user3" "Third principal incorrect"
        }

        test "Multiple principals work end-to-end with ssh-keygen" {
            use ca = RSA.Create()
            let caPubKey = ca.ExportRSAPublicKeyPem() |> PublicKey.OfRsaPublicKeyPem
            let pubKeyToSign = TestData.testSshKey |> PublicKey.OfSshPublicKey
            let certInfo =
                CertificateInfo("multiuser", pubKeyToSign, caPubKey,
                                TestData.nonce,
                                Serial=123UL, 
                                Principals=["alice"; "bob"; "charlie"],
                                ValidAfter=DateTimeOffset(DateTime(2025, 6, 13, 8, 0, 0)),
                                ValidBefore=DateTimeOffset(DateTime(2025, 6, 13, 8, 0, 0)).AddHours 2
                )
            let certAuth = CertificateAuthority(fun ms -> ca.SignData(ms, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1))
            let certLine = certAuth.SignAndSerialize(certInfo, "multiuser@domain")
            let tempFile = Path.GetTempFileName()
            File.WriteAllText(tempFile, certLine)
            let cmdResult =
                cli {
                    Exec "/usr/bin/ssh-keygen"
                    Arguments $"-L -f {tempFile}"
                } |> Command.execute
            let output = cmdResult |> Output.throwIfErrored |> Output.toText
            let out = new StringReader(output)
            
            // Skip until we find the Serial line
            let mutable line = out.ReadLine()
            while not (isNull line) && not (line.Trim().StartsWith("Serial:")) do
                line <- out.ReadLine()
            
            // Should be at Serial line now
            Expect.stringContains (line.Trim()) "Serial: 123" "Serial number incorrect"
            
            // Read Valid line
            Expect.stringContains 
                (out.ReadLine().Trim()) 
                "Valid: from 2025-06-13T08:00:00 to 2025-06-13T10:00:00"
                "Validity period incorrect"
            
            // Read Principals header
            Expect.equal
                (out.ReadLine().Trim())
                "Principals:"
                "Missing Principals header"
            
            // Read principals
            Expect.equal
                (out.ReadLine().Trim())
                "alice"
                "First principal should be alice"
            Expect.equal
                (out.ReadLine().Trim())
                "bob"
                "Second principal should be bob"
            Expect.equal
                (out.ReadLine().Trim())
                "charlie"
                "Third principal should be charlie"
        }

        test "Empty principals array is allowed" {
            use ca = RSA.Create()
            let caPubKey = ca.ExportRSAPublicKeyPem() |> PublicKey.OfRsaPublicKeyPem
            let pubKeyToSign = TestData.testSshKey |> PublicKey.OfSshPublicKey
            
            let certInfo = CertificateInfo("testkey", pubKeyToSign, caPubKey, TestData.nonce)
            certInfo.Principals <- Array.Empty<string>()
            
            let principals = certInfo.Principals |> Seq.toList
            Expect.isEmpty principals "Principals should be empty"
        }

        test "Serial number can be set and retrieved" {
            use ca = RSA.Create()
            let caPubKey = ca.ExportRSAPublicKeyPem() |> PublicKey.OfRsaPublicKeyPem
            let pubKeyToSign = TestData.testSshKey |> PublicKey.OfSshPublicKey
            
            let certInfo = CertificateInfo("testkey", pubKeyToSign, caPubKey, TestData.nonce)
            certInfo.Serial <- 999999UL
            
            Expect.equal certInfo.Serial 999999UL "Serial number should match"
        }

        test "KeyId can be modified" {
            use ca = RSA.Create()
            let caPubKey = ca.ExportRSAPublicKeyPem() |> PublicKey.OfRsaPublicKeyPem
            let pubKeyToSign = TestData.testSshKey |> PublicKey.OfSshPublicKey
            
            let certInfo = CertificateInfo("original", pubKeyToSign, caPubKey, TestData.nonce)
            certInfo.KeyId <- "modified-key-id"
            
            Expect.equal certInfo.KeyId "modified-key-id" "KeyId should be updated"
        }

        test "ValidAfter and ValidBefore can be set" {
            use ca = RSA.Create()
            let caPubKey = ca.ExportRSAPublicKeyPem() |> PublicKey.OfRsaPublicKeyPem
            let pubKeyToSign = TestData.testSshKey |> PublicKey.OfSshPublicKey
            
            let certInfo = CertificateInfo("testkey", pubKeyToSign, caPubKey, TestData.nonce)
            let validAfter = DateTimeOffset(DateTime(2026, 1, 1, 0, 0, 0))
            let validBefore = DateTimeOffset(DateTime(2027, 1, 1, 0, 0, 0))
            certInfo.ValidAfter <- validAfter
            certInfo.ValidBefore <- validBefore
            
            Expect.equal certInfo.ValidAfter validAfter "ValidAfter should match"
            Expect.equal certInfo.ValidBefore validBefore "ValidBefore should match"
        }

        test "CriticalOptions can be set" {
            use ca = RSA.Create()
            let caPubKey = ca.ExportRSAPublicKeyPem() |> PublicKey.OfRsaPublicKeyPem
            let pubKeyToSign = TestData.testSshKey |> PublicKey.OfSshPublicKey
            
            let certInfo = CertificateInfo("testkey", pubKeyToSign, caPubKey, TestData.nonce)
            certInfo.CriticalOptions <- ["force-command=/bin/bash"; "source-address=192.168.1.0/24"]
            
            let options = certInfo.CriticalOptions |> Seq.toList
            Expect.equal options.Length 2 "Should have 2 critical options"
            Expect.equal options.[0] "force-command=/bin/bash" "First option incorrect"
            Expect.equal options.[1] "source-address=192.168.1.0/24" "Second option incorrect"
        }

        test "Extensions can be set" {
            use ca = RSA.Create()
            let caPubKey = ca.ExportRSAPublicKeyPem() |> PublicKey.OfRsaPublicKeyPem
            let pubKeyToSign = TestData.testSshKey |> PublicKey.OfSshPublicKey
            
            let certInfo = CertificateInfo("testkey", pubKeyToSign, caPubKey, TestData.nonce)
            certInfo.Extensions <- ["permit-X11-forwarding"; "permit-agent-forwarding"; "permit-port-forwarding"]
            
            let extensions = certInfo.Extensions |> Seq.toList
            Expect.equal extensions.Length 3 "Should have 3 extensions"
            Expect.equal extensions.[0] "permit-X11-forwarding" "First extension incorrect"
            Expect.equal extensions.[1] "permit-agent-forwarding" "Second extension incorrect"
            Expect.equal extensions.[2] "permit-port-forwarding" "Third extension incorrect"
        }

        test "Nonce can be changed after construction" {
            use ca = RSA.Create()
            let caPubKey = ca.ExportRSAPublicKeyPem() |> PublicKey.OfRsaPublicKeyPem
            let pubKeyToSign = TestData.testSshKey |> PublicKey.OfSshPublicKey
            
            let certInfo = CertificateInfo("testkey", pubKeyToSign, caPubKey, TestData.nonce)
            let newNonce = Array.create 32 99uy
            certInfo.Nonce <- newNonce
            
            Expect.equal certInfo.Nonce newNonce "Nonce should be updated"
        }

        test "PublicKeyToSign property returns correct key" {
            use ca = RSA.Create()
            let caPubKey = ca.ExportRSAPublicKeyPem() |> PublicKey.OfRsaPublicKeyPem
            let pubKeyToSign = TestData.testSshKey |> PublicKey.OfSshPublicKey
            
            let certInfo = CertificateInfo("testkey", pubKeyToSign, caPubKey, TestData.nonce)
            
            Expect.equal certInfo.PublicKeyToSign pubKeyToSign "PublicKeyToSign should match"
        }

        test "CaPublicKey property returns correct key" {
            use ca = RSA.Create()
            let caPubKey = ca.ExportRSAPublicKeyPem() |> PublicKey.OfRsaPublicKeyPem
            let pubKeyToSign = TestData.testSshKey |> PublicKey.OfSshPublicKey
            
            let certInfo = CertificateInfo("testkey", pubKeyToSign, caPubKey, TestData.nonce)
            
            Expect.equal certInfo.CaPublicKey caPubKey "CaPublicKey should match"
        }

        test "Special characters in KeyId are preserved" {
            use ca = RSA.Create()
            let caPubKey = ca.ExportRSAPublicKeyPem() |> PublicKey.OfRsaPublicKeyPem
            let pubKeyToSign = TestData.testSshKey |> PublicKey.OfSshPublicKey
            let specialKeyId = "test-key_123@domain.com"
            
            let certInfo = CertificateInfo(specialKeyId, pubKeyToSign, caPubKey, TestData.nonce)
            
            Expect.equal certInfo.KeyId specialKeyId "KeyId with special chars should be preserved"
        }

        test "Special characters in principals are preserved" {
            use ca = RSA.Create()
            let caPubKey = ca.ExportRSAPublicKeyPem() |> PublicKey.OfRsaPublicKeyPem
            let pubKeyToSign = TestData.testSshKey |> PublicKey.OfSshPublicKey
            
            let certInfo = CertificateInfo("testkey", pubKeyToSign, caPubKey, TestData.nonce)
            certInfo.Principals <- ["user@host.com"; "user-name_123"]
            
            let principals = certInfo.Principals |> Seq.toList
            Expect.equal principals.[0] "user@host.com" "Principal with @ should be preserved"
            Expect.equal principals.[1] "user-name_123" "Principal with special chars should be preserved"
        }
    ]

[<Tests>]
let certificateAuthorityTests =
    testList "CertificateAuthority Tests" [
        test "Sign returns byte array" {
            use ca = RSA.Create()
            let caPubKey = ca.ExportRSAPublicKeyPem() |> PublicKey.OfRsaPublicKeyPem
            let pubKeyToSign = TestData.testSshKey |> PublicKey.OfSshPublicKey
            let certInfo =
                CertificateInfo("testkey", pubKeyToSign, caPubKey,
                                TestData.nonce,
                                Serial=1UL, Principals=["testuser"],
                                ValidAfter=DateTimeOffset(DateTime(2025, 6, 13, 8, 0, 0)),
                                ValidBefore=DateTimeOffset(DateTime(2025, 6, 13, 8, 0, 0)).AddHours 2
                )
            let certAuth = CertificateAuthority(fun ms -> ca.SignData(ms, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1))
            
            let certBytes = certAuth.Sign(certInfo)
            
            Expect.isNotNull certBytes "Certificate bytes should not be null"
            Expect.isGreaterThan certBytes.Length 0 "Certificate bytes should not be empty"
        }

        test "Sign throws ArgumentNullException for null certInfo" {
            use ca = RSA.Create()
            let certAuth = CertificateAuthority(fun ms -> ca.SignData(ms, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1))
            
            Expect.throws
                (fun () -> certAuth.Sign(null) |> ignore)
                "Should throw ArgumentNullException for null certInfo"
        }

        test "Sign throws ArgumentException for invalid nonce length" {
            use ca = RSA.Create()
            let caPubKey = ca.ExportRSAPublicKeyPem() |> PublicKey.OfRsaPublicKeyPem
            let pubKeyToSign = TestData.testSshKey |> PublicKey.OfSshPublicKey
            let invalidNonce = Array.create 16 0uy // Wrong size
            let certInfo = CertificateInfo("testkey", pubKeyToSign, caPubKey, invalidNonce)
            let certAuth = CertificateAuthority(fun ms -> ca.SignData(ms, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1))
            
            Expect.throws
                (fun () -> certAuth.Sign(certInfo) |> ignore)
                "Should throw ArgumentException for nonce not 32 bytes"
        }

        test "SignAndSerialize with null comment omits comment" {
            use ca = RSA.Create()
            let caPubKey = ca.ExportRSAPublicKeyPem() |> PublicKey.OfRsaPublicKeyPem
            let pubKeyToSign = TestData.testSshKey |> PublicKey.OfSshPublicKey
            let certInfo =
                CertificateInfo("testkey", pubKeyToSign, caPubKey,
                                TestData.nonce,
                                Serial=1UL, Principals=["testuser"],
                                ValidAfter=DateTimeOffset(DateTime(2025, 6, 13, 8, 0, 0)),
                                ValidBefore=DateTimeOffset(DateTime(2025, 6, 13, 8, 0, 0)).AddHours 2
                )
            let certAuth = CertificateAuthority(fun ms -> ca.SignData(ms, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1))
            
            let certLine = certAuth.SignAndSerialize(certInfo, null)
            
            let parts = certLine.Split(' ')
            Expect.equal parts.Length 2 "Should have only algorithm and key without comment"
            Expect.equal parts.[0] "rsa-sha2-512-cert-v01@openssh.com" "Algorithm should be correct"
        }

        test "SignAndSerialize with empty comment omits comment" {
            use ca = RSA.Create()
            let caPubKey = ca.ExportRSAPublicKeyPem() |> PublicKey.OfRsaPublicKeyPem
            let pubKeyToSign = TestData.testSshKey |> PublicKey.OfSshPublicKey
            let certInfo =
                CertificateInfo("testkey", pubKeyToSign, caPubKey,
                                TestData.nonce,
                                Serial=1UL, Principals=["testuser"],
                                ValidAfter=DateTimeOffset(DateTime(2025, 6, 13, 8, 0, 0)),
                                ValidBefore=DateTimeOffset(DateTime(2025, 6, 13, 8, 0, 0)).AddHours 2
                )
            let certAuth = CertificateAuthority(fun ms -> ca.SignData(ms, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1))
            
            let certLine = certAuth.SignAndSerialize(certInfo, "")
            
            let parts = certLine.Split(' ')
            Expect.equal parts.Length 2 "Should have only algorithm and key without comment"
        }

        test "SignAndSerialize with whitespace comment omits comment" {
            use ca = RSA.Create()
            let caPubKey = ca.ExportRSAPublicKeyPem() |> PublicKey.OfRsaPublicKeyPem
            let pubKeyToSign = TestData.testSshKey |> PublicKey.OfSshPublicKey
            let certInfo =
                CertificateInfo("testkey", pubKeyToSign, caPubKey,
                                TestData.nonce,
                                Serial=1UL, Principals=["testuser"],
                                ValidAfter=DateTimeOffset(DateTime(2025, 6, 13, 8, 0, 0)),
                                ValidBefore=DateTimeOffset(DateTime(2025, 6, 13, 8, 0, 0)).AddHours 2
                )
            let certAuth = CertificateAuthority(fun ms -> ca.SignData(ms, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1))
            
            let certLine = certAuth.SignAndSerialize(certInfo, "   ")
            
            let parts = certLine.Split(' ')
            Expect.equal parts.Length 2 "Should have only algorithm and key without comment"
        }

        test "SignAndSerialize with comment includes comment" {
            use ca = RSA.Create()
            let caPubKey = ca.ExportRSAPublicKeyPem() |> PublicKey.OfRsaPublicKeyPem
            let pubKeyToSign = TestData.testSshKey |> PublicKey.OfSshPublicKey
            let certInfo =
                CertificateInfo("testkey", pubKeyToSign, caPubKey,
                                TestData.nonce,
                                Serial=1UL, Principals=["testuser"],
                                ValidAfter=DateTimeOffset(DateTime(2025, 6, 13, 8, 0, 0)),
                                ValidBefore=DateTimeOffset(DateTime(2025, 6, 13, 8, 0, 0)).AddHours 2
                )
            let certAuth = CertificateAuthority(fun ms -> ca.SignData(ms, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1))
            
            let certLine = certAuth.SignAndSerialize(certInfo, "user@domain")
            
            let parts = certLine.Split(' ')
            Expect.equal parts.Length 3 "Should have algorithm, key, and comment"
            Expect.equal parts.[2] "user@domain" "Comment should match"
        }

        test "SignAndSerialize throws ArgumentNullException for null certInfo" {
            use ca = RSA.Create()
            let certAuth = CertificateAuthority(fun ms -> ca.SignData(ms, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1))
            
            Expect.throws
                (fun () -> certAuth.SignAndSerialize(null, "comment") |> ignore)
                "Should throw ArgumentNullException for null certInfo"
        }

        test "Different nonces produce different certificates" {
            use ca = RSA.Create()
            let caPubKey = ca.ExportRSAPublicKeyPem() |> PublicKey.OfRsaPublicKeyPem
            let pubKeyToSign = TestData.testSshKey |> PublicKey.OfSshPublicKey
            let nonce1 = Array.create 32 1uy
            let nonce2 = Array.create 32 2uy
            
            let certInfo1 =
                CertificateInfo("testkey", pubKeyToSign, caPubKey,
                                nonce1,
                                Serial=1UL, Principals=["testuser"],
                                ValidAfter=DateTimeOffset(DateTime(2025, 6, 13, 8, 0, 0)),
                                ValidBefore=DateTimeOffset(DateTime(2025, 6, 13, 8, 0, 0)).AddHours 2
                )
            let certInfo2 =
                CertificateInfo("testkey", pubKeyToSign, caPubKey,
                                nonce2,
                                Serial=1UL, Principals=["testuser"],
                                ValidAfter=DateTimeOffset(DateTime(2025, 6, 13, 8, 0, 0)),
                                ValidBefore=DateTimeOffset(DateTime(2025, 6, 13, 8, 0, 0)).AddHours 2
                )
            
            let certAuth = CertificateAuthority(fun ms -> ca.SignData(ms, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1))
            let cert1 = certAuth.SignAndSerialize(certInfo1, "test")
            let cert2 = certAuth.SignAndSerialize(certInfo2, "test")
            
            Expect.notEqual cert1 cert2 "Different nonces should produce different certificates"
        }
    ]

[<Tests>]
let certificateAuthorityAsyncTests =
    testList "CertificateAuthorityAsync Tests" [
        testTask "SignAsync with cancellation token returns byte array" {
            let ca = RSA.Create()
            try
                let caPubKey = ca.ExportRSAPublicKeyPem() |> PublicKey.OfRsaPublicKeyPem
                let pubKeyToSign = TestData.testSshKey |> PublicKey.OfSshPublicKey
                let certInfo =
                    CertificateInfo("testkey", pubKeyToSign, caPubKey,
                                    TestData.nonce,
                                    Serial=1UL, Principals=["testuser"],
                                    ValidAfter=DateTimeOffset(DateTime(2025, 6, 13, 8, 0, 0)),
                                    ValidBefore=DateTimeOffset(DateTime(2025, 6, 13, 8, 0, 0)).AddHours 2
                    )
                let asyncSigner =
                    fun (stream:Stream) (_:System.Threading.CancellationToken) ->
                        backgroundTask {
                            return ca.SignData(stream, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1)
                        }
                let certAuth = CertificateAuthorityAsync(asyncSigner)
                let cts = new System.Threading.CancellationTokenSource()
                
                let! (certBytes:byte array) = certAuth.SignAsync(certInfo, cts.Token)
                
                Expect.isNotNull certBytes "Certificate bytes should not be null"
                Expect.isGreaterThan certBytes.Length 0 "Certificate bytes should not be empty"
            finally
                ca.Dispose()
        }

        testTask "SignAsync without cancellation token works" {
            let ca = RSA.Create()
            try
                let caPubKey = ca.ExportRSAPublicKeyPem() |> PublicKey.OfRsaPublicKeyPem
                let pubKeyToSign = TestData.testSshKey |> PublicKey.OfSshPublicKey
                let certInfo =
                    CertificateInfo("testkey", pubKeyToSign, caPubKey,
                                    TestData.nonce,
                                    Serial=1UL, Principals=["testuser"],
                                    ValidAfter=DateTimeOffset(DateTime(2025, 6, 13, 8, 0, 0)),
                                    ValidBefore=DateTimeOffset(DateTime(2025, 6, 13, 8, 0, 0)).AddHours 2
                    )
                let asyncSigner =
                    fun (stream:Stream) (_:System.Threading.CancellationToken) ->
                        backgroundTask {
                            return ca.SignData(stream, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1)
                        }
                let certAuth = CertificateAuthorityAsync(asyncSigner)
                
                let! (certBytes:byte array) = certAuth.SignAsync(certInfo)
                
                Expect.isNotNull certBytes "Certificate bytes should not be null"
                Expect.isGreaterThan certBytes.Length 0 "Certificate bytes should not be empty"
            finally
                ca.Dispose()
        }

        testTask "SignAsync throws ArgumentNullException for null certInfo" {
            let ca = RSA.Create()
            try
                let asyncSigner =
                    fun (stream:Stream) (_:System.Threading.CancellationToken) ->
                        backgroundTask {
                            return ca.SignData(stream, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1)
                        }
                let certAuth = CertificateAuthorityAsync(asyncSigner)
                
                let! result =
                    Async.AwaitTask(
                        task {
                            try
                                let! _ = certAuth.SignAsync(null)
                                return false
                            with
                            | :? ArgumentNullException -> return true
                            | _ -> return false
                        }
                    )
                Expect.isTrue result "Should throw ArgumentNullException for null certInfo"
            finally
                ca.Dispose()
        }

        testTask "SignAsync throws ArgumentException for invalid nonce length" {
            let ca = RSA.Create()
            try
                let caPubKey = ca.ExportRSAPublicKeyPem() |> PublicKey.OfRsaPublicKeyPem
                let pubKeyToSign = TestData.testSshKey |> PublicKey.OfSshPublicKey
                let invalidNonce = Array.create 16 0uy // Wrong size
                let certInfo = CertificateInfo("testkey", pubKeyToSign, caPubKey, invalidNonce)
                let asyncSigner =
                    fun (stream:Stream) (_:System.Threading.CancellationToken) ->
                        backgroundTask {
                            return ca.SignData(stream, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1)
                        }
                let certAuth = CertificateAuthorityAsync(asyncSigner)
                
                let! result =
                    Async.AwaitTask(
                        task {
                            try
                                let! _ = certAuth.SignAsync(certInfo)
                                return false
                            with
                            | :? ArgumentException -> return true
                            | _ -> return false
                        }
                    )
                Expect.isTrue result "Should throw ArgumentException for invalid nonce"
            finally
                ca.Dispose()
        }

        testTask "SignAndSerializeAsync with null comment omits comment" {
            let ca = RSA.Create()
            try
                let caPubKey = ca.ExportRSAPublicKeyPem() |> PublicKey.OfRsaPublicKeyPem
                let pubKeyToSign = TestData.testSshKey |> PublicKey.OfSshPublicKey
                let certInfo =
                    CertificateInfo("testkey", pubKeyToSign, caPubKey,
                                    TestData.nonce,
                                    Serial=1UL, Principals=["testuser"],
                                    ValidAfter=DateTimeOffset(DateTime(2025, 6, 13, 8, 0, 0)),
                                    ValidBefore=DateTimeOffset(DateTime(2025, 6, 13, 8, 0, 0)).AddHours 2
                    )
                let asyncSigner =
                    fun (stream:Stream) (_:System.Threading.CancellationToken) ->
                        backgroundTask {
                            return ca.SignData(stream, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1)
                        }
                let certAuth = CertificateAuthorityAsync(asyncSigner)
                
                let! (certLine:string) = certAuth.SignAndSerializeAsync(certInfo, null)
                
                let parts = certLine.Split(' ')
                Expect.equal parts.Length 2 "Should have only algorithm and key without comment"
                Expect.equal parts.[0] "rsa-sha2-512-cert-v01@openssh.com" "Algorithm should be correct"
            finally
                ca.Dispose()
        }

        testTask "SignAndSerializeAsync with empty comment omits comment" {
            let ca = RSA.Create()
            try
                let caPubKey = ca.ExportRSAPublicKeyPem() |> PublicKey.OfRsaPublicKeyPem
                let pubKeyToSign = TestData.testSshKey |> PublicKey.OfSshPublicKey
                let certInfo =
                    CertificateInfo("testkey", pubKeyToSign, caPubKey,
                                    TestData.nonce,
                                    Serial=1UL, Principals=["testuser"],
                                    ValidAfter=DateTimeOffset(DateTime(2025, 6, 13, 8, 0, 0)),
                                    ValidBefore=DateTimeOffset(DateTime(2025, 6, 13, 8, 0, 0)).AddHours 2
                    )
                let asyncSigner =
                    fun (stream:Stream) (_:System.Threading.CancellationToken) ->
                        backgroundTask {
                            return ca.SignData(stream, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1)
                        }
                let certAuth = CertificateAuthorityAsync(asyncSigner)
                
                let! (certLine:string) = certAuth.SignAndSerializeAsync(certInfo, "")
                
                let parts = certLine.Split(' ')
                Expect.equal parts.Length 2 "Should have only algorithm and key without comment"
            finally
                ca.Dispose()
        }

        testTask "SignAndSerializeAsync with comment includes comment" {
            let ca = RSA.Create()
            try
                let caPubKey = ca.ExportRSAPublicKeyPem() |> PublicKey.OfRsaPublicKeyPem
                let pubKeyToSign = TestData.testSshKey |> PublicKey.OfSshPublicKey
                let certInfo =
                    CertificateInfo("testkey", pubKeyToSign, caPubKey,
                                    TestData.nonce,
                                    Serial=1UL, Principals=["testuser"],
                                    ValidAfter=DateTimeOffset(DateTime(2025, 6, 13, 8, 0, 0)),
                                    ValidBefore=DateTimeOffset(DateTime(2025, 6, 13, 8, 0, 0)).AddHours 2
                    )
                let asyncSigner =
                    fun (stream:Stream) (_:System.Threading.CancellationToken) ->
                        backgroundTask {
                            return ca.SignData(stream, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1)
                        }
                let certAuth = CertificateAuthorityAsync(asyncSigner)
                
                let! (certLine:string) = certAuth.SignAndSerializeAsync(certInfo, "user@domain")
                
                let parts = certLine.Split(' ')
                Expect.equal parts.Length 3 "Should have algorithm, key, and comment"
                Expect.equal parts.[2] "user@domain" "Comment should match"
            finally
                ca.Dispose()
        }

        testTask "SignAndSerializeAsync throws ArgumentNullException for null certInfo" {
            let ca = RSA.Create()
            try
                let asyncSigner =
                    fun (stream:Stream) (_:System.Threading.CancellationToken) ->
                        backgroundTask {
                            return ca.SignData(stream, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1)
                        }
                let certAuth = CertificateAuthorityAsync(asyncSigner)
                
                let! result =
                    Async.AwaitTask(
                        task {
                            try
                                let! _ = certAuth.SignAndSerializeAsync(null, "comment")
                                return false
                            with
                            | :? ArgumentNullException -> return true
                            | _ -> return false
                        }
                    )
                Expect.isTrue result "Should throw ArgumentNullException for null certInfo"
            finally
                ca.Dispose()
        }

        testTask "Cancellation token is passed through to signing function" {
            let ca = RSA.Create()
            try
                let caPubKey = ca.ExportRSAPublicKeyPem() |> PublicKey.OfRsaPublicKeyPem
                let pubKeyToSign = TestData.testSshKey |> PublicKey.OfSshPublicKey
                let certInfo =
                    CertificateInfo("testkey", pubKeyToSign, caPubKey,
                                    TestData.nonce,
                                    Serial=1UL, Principals=["testuser"],
                                    ValidAfter=DateTimeOffset(DateTime(2025, 6, 13, 8, 0, 0)),
                                    ValidBefore=DateTimeOffset(DateTime(2025, 6, 13, 8, 0, 0)).AddHours 2
                    )
                let mutable tokenPassed = System.Threading.CancellationToken.None
                let asyncSigner =
                    fun (stream:Stream) (ct:System.Threading.CancellationToken) ->
                        backgroundTask {
                            tokenPassed <- ct
                            return ca.SignData(stream, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1)
                        }
                let certAuth = CertificateAuthorityAsync(asyncSigner)
                let cts = new System.Threading.CancellationTokenSource()
                
                let! _ = certAuth.SignAsync(certInfo, cts.Token)
                
                Expect.equal tokenPassed cts.Token "Cancellation token should be passed to signing function"
            finally
                ca.Dispose()
        }

        testTask "Different nonces produce different certificates async" {
            let ca = RSA.Create()
            try
                let caPubKey = ca.ExportRSAPublicKeyPem() |> PublicKey.OfRsaPublicKeyPem
                let pubKeyToSign = TestData.testSshKey |> PublicKey.OfSshPublicKey
                let nonce1 = Array.create 32 1uy
                let nonce2 = Array.create 32 2uy
                
                let certInfo1 =
                    CertificateInfo("testkey", pubKeyToSign, caPubKey,
                                    nonce1,
                                    Serial=1UL, Principals=["testuser"],
                                    ValidAfter=DateTimeOffset(DateTime(2025, 6, 13, 8, 0, 0)),
                                    ValidBefore=DateTimeOffset(DateTime(2025, 6, 13, 8, 0, 0)).AddHours 2
                    )
                let certInfo2 =
                    CertificateInfo("testkey", pubKeyToSign, caPubKey,
                                    nonce2,
                                    Serial=1UL, Principals=["testuser"],
                                    ValidAfter=DateTimeOffset(DateTime(2025, 6, 13, 8, 0, 0)),
                                    ValidBefore=DateTimeOffset(DateTime(2025, 6, 13, 8, 0, 0)).AddHours 2
                    )
                let asyncSigner =
                    fun (stream:Stream) (_:System.Threading.CancellationToken) ->
                        backgroundTask {
                            return ca.SignData(stream, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1)
                        }
                
                let certAuth = CertificateAuthorityAsync(asyncSigner)
                let! cert1 = certAuth.SignAndSerializeAsync(certInfo1, "test")
                let! cert2 = certAuth.SignAndSerializeAsync(certInfo2, "test")
                
                Expect.notEqual cert1 cert2 "Different nonces should produce different certificates"
            finally
                ca.Dispose()
        }
    ]
