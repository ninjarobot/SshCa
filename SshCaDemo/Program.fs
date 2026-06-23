open System
open System.IO
open System.Security.Cryptography
open SshCA

// ASCII art banner
let printBanner() =
    printfn ""
    printfn "  ╔═══════════════════════════════════════════════════════════╗"
    printfn "  ║                                                           ║"
    printfn "  ║     🔐  SSH Certificate Authority Demo  🔐                ║"
    printfn "  ║                                                           ║"
    printfn "  ║     Sign SSH keys like a boss!                            ║"
    printfn "  ║                                                           ║"
    printfn "  ╚═══════════════════════════════════════════════════════════╝"
    printfn ""

let printStep (step: int) (description: string) =
    printfn ""
    printfn $"═══ Step {step}: {description}"
    printfn ""

let printSuccess (message: string) =
    printfn $"✅ {message}"

let printInfo (message: string) =
    printfn $"ℹ️  {message}"

let printKey (label: string) (content: string) =
    let truncated = if content.Length > 80 then content.Substring(0, 77) + "..." else content
    printfn $"   {label}: {truncated}"

[<EntryPoint>]
let main argv =
    try
        printBanner()
        
        // Step 1: Generate a Certificate Authority (CA) key pair
        printStep 1 "Creating a Certificate Authority (CA)"
        use ca = RSA.Create(2048)
        let caPubKeyPem = ca.ExportRSAPublicKeyPem()
        let caPubKey = PublicKey.OfRsaPublicKeyPem(caPubKeyPem)
        let caSshPubKey = PublicKey.ToSshPublicKey(caPubKey)
        printSuccess "Generated CA key pair"
        printKey "CA Public Key" caSshPubKey
        
        // Step 2: Generate a user SSH key pair
        printStep 2 "Generating a user SSH key pair"
        use userKey = RSA.Create(2048)
        let userPubKeyPem = userKey.ExportRSAPublicKeyPem()
        let userPubKey = PublicKey.OfRsaPublicKeyPem(userPubKeyPem)
        let userSshPubKey = PublicKey.ToSshPublicKey(userPubKey)
        printSuccess "Generated user key pair"
        printKey "User Public Key" userSshPubKey
        
        // Step 3: Create certificate information
        printStep 3 "Creating certificate information"
        let certInfo = 
            CertificateInfo(
                "demo-user",           // Key ID - shows in SSH logs
                userPubKey,            // The public key to sign
                caPubKey,              // The CA's public key
                Serial = 1UL,
                Principals = ["ubuntu"; "admin"],  // Users this cert can login as
                ValidAfter = DateTimeOffset.Now,
                ValidBefore = DateTimeOffset.Now.AddHours(8.0)  // Valid for 8 hours
            )
        certInfo.Extensions <- ["permit-pty"; "permit-port-forwarding"; "permit-user-rc"]
        printSuccess "Created certificate with following details:"
        printInfo $"Key ID: {certInfo.KeyId}"
        let validFromStr = certInfo.ValidAfter.ToString("yyyy-MM-dd HH:mm:ss")
        let validUntilStr = certInfo.ValidBefore.ToString("yyyy-MM-dd HH:mm:ss")
        printInfo $"Valid From: {validFromStr}"
        printInfo $"Valid Until: {validUntilStr}"
        let principalsStr = String.Join(", ", certInfo.Principals)
        let extensionsStr = String.Join(", ", certInfo.Extensions)
        printInfo $"Principals (allowed users): {principalsStr}"
        printInfo $"Extensions: {extensionsStr}"
        
        // Step 4: Sign the certificate
        printStep 4 "Signing the certificate with CA private key"
        let signer = Func<Stream, byte array>(fun ms -> ca.SignData(ms, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1))
        let certAuth = CertificateAuthority(signer)
        let signedCert = certAuth.SignAndSerialize(certInfo, "demo-user@demo-server")
        printSuccess "Certificate signed successfully!"
        printKey "Signed Certificate" signedCert
        
        // Step 5: Save everything to files
        printStep 5 "Saving files to disk"
        let demoDir = Path.Combine(Path.GetTempPath(), "sshca-demo")
        Directory.CreateDirectory(demoDir) |> ignore
        
        let caKeyFile = Path.Combine(demoDir, "ca_key.pem")
        let caPubFile = Path.Combine(demoDir, "ca_key.pub")
        let userPubFile = Path.Combine(demoDir, "id_rsa.pub")
        let certFile = Path.Combine(demoDir, "id_rsa-cert.pub")
        
        File.WriteAllText(caKeyFile, ca.ExportRSAPrivateKeyPem())
        File.WriteAllText(caPubFile, caSshPubKey)
        File.WriteAllText(userPubFile, userSshPubKey)
        File.WriteAllText(certFile, signedCert)
        
        printSuccess $"Saved files to: {demoDir}"
        printInfo "CA private key: ca_key.pem"
        printInfo "CA public key: ca_key.pub"
        printInfo "User public key: id_rsa.pub"
        printInfo "Signed certificate: id_rsa-cert.pub"
        
        // Step 6: Show how to use the certificate
        printStep 6 "How to use your signed certificate"
        printfn "  To use this certificate for SSH authentication:"
        printfn ""
        printfn "  1. On the SSH server, add the CA public key to sshd_config:"
        printfn "     TrustedUserCAKeys /etc/ssh/ca_key.pub"
        printfn ""
        printfn "  2. Copy the CA public key to the server:"
        printfn $"     scp {caPubFile} server:/etc/ssh/ca_key.pub"
        printfn ""
        printfn "  3. Use your signed certificate to connect:"
        printfn $"     ssh -i ~/.ssh/id_rsa -o CertificateFile={certFile} ubuntu@server"
        printfn ""
        printfn "  The server will trust any certificate signed by your CA!"
        printfn ""
        
        // Summary
        printfn ""
        printfn "═══════════════════════════════════════════════════════════════"
        printfn ""
        printfn "🎉 Demo Complete! 🎉"
        printfn ""
        printfn "Key Benefits of SSH Certificate Authentication:"
        printfn "  • No more managing authorized_keys on every server"
        printfn "  • Centralized access control via CA"
        printfn "  • Time-limited access (certificates expire)"
        printfn "  • Easy to audit (Key IDs show in logs)"
        printfn "  • Principal-based authorization"
        printfn ""
        printfn "Learn more: https://github.com/ninjarobot/SshCA"
        printfn ""
        printfn "═══════════════════════════════════════════════════════════════"
        printfn ""
        
        0
    with ex ->
        printfn ""
        printfn $"❌ Error: {ex.Message}"
        printfn $"   {ex.StackTrace}"
        1
