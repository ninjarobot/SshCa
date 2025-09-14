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
            let caPubKey = ca.ExportRSAPublicKeyPem() |> PublicKey.ofRsaPublicKeyPem
            let pubKeyToSign = TestData.testSshKey |> PublicKey.ofSshPublicKey
            use certContents =
                SshCertificate.buildCertificateContentStream
                    (Some TestData.nonce)
                    pubKeyToSign
                    0UL
                    "testkey"
                    ["someUser"]
                    (DateTimeOffset(DateTime(2025, 6, 13, 8, 0, 0)))
                    (DateTimeOffset(DateTime(2025, 6, 13, 8, 0, 0)).AddHours 2)
                    []
                    []
                    caPubKey
            let signature = certContents |> SshCertificate.sign (fun ms -> ca.SignData(ms, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1))
            signature |> SshCertificate.appendSignature certContents
            let certBytes = SshCertificate.getCertificateBytes certContents
            let certLine = certBytes |> SshCertificate.toSshFormat "testkey@domain"
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
    ]
