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
