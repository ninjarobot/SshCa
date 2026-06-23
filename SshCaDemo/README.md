# 🔐 SshCA Demo - Sign SSH Keys Like a Boss!

This is an interactive demo that shows you exactly how to use the **SshCA** library to sign SSH public keys with Certificate Authority (CA) certificates.

## What Does This Demo Show?

This demo walks you through the complete process of SSH certificate authentication:

1. **Creating a Certificate Authority (CA)** - Generate a CA key pair that will be trusted by your SSH servers
2. **Generating a user SSH key** - Create a user's public/private key pair
3. **Creating certificate information** - Define who can login, where, and for how long
4. **Signing the certificate** - Use the CA private key to sign the user's public key
5. **Saving the files** - Export everything you need to use SSH certificates
6. **How to use it** - Clear instructions on setting up your SSH server and client

## Why SSH Certificates Are Awesome

✅ **No more managing authorized_keys on every server**  
✅ **Centralized access control via CA**  
✅ **Time-limited access (certificates expire)**  
✅ **Easy to audit (Key IDs show in logs)**  
✅ **Principal-based authorization**  

## Running the Demo

```bash
dotnet run
```

That's it! The demo is completely self-contained and doesn't require any external services.

## What You'll See

The demo produces beautiful, step-by-step output with emojis and clear formatting:

```
  ╔═══════════════════════════════════════════════════════════╗
  ║                                                           ║
  ║     🔐  SSH Certificate Authority Demo  🔐                ║
  ║                                                           ║
  ║     Sign SSH keys like a boss!                            ║
  ║                                                           ║
  ╚═══════════════════════════════════════════════════════════╝

═══ Step 1: Creating a Certificate Authority (CA)
✅ Generated CA key pair
...
```

## Files Generated

The demo creates several files in `/tmp/sshca-demo/`:

- `ca_key.pem` - The CA private key (keep this secret!)
- `ca_key.pub` - The CA public key (add to your SSH servers)
- `id_rsa.pub` - A sample user public key
- `id_rsa-cert.pub` - The signed certificate (ready to use!)

## Real-World Usage

In production, you'd typically:

1. **Store your CA private key securely** - Use Azure Key Vault, AWS KMS, or an HSM
2. **Distribute the CA public key** to all your SSH servers
3. **Sign user keys** with appropriate principals, expiry times, and extensions
4. **Users authenticate** with their signed certificates instead of managing authorized_keys

## Learn More

- [SshCA GitHub Repository](https://github.com/ninjarobot/SshCA)
- [SshCA on NuGet](https://www.nuget.org/packages/SshCA/)

## Code Highlights

This demo shows how to:

```fsharp
// Create a CA
use ca = RSA.Create(2048)
let caPubKey = PublicKey.OfRsaPublicKeyPem(ca.ExportRSAPublicKeyPem())

// Create certificate info
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

// Sign it!
let signer = Func<Stream, byte array>(fun ms -> 
    ca.SignData(ms, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1))
let certAuth = CertificateAuthority(signer)
let signedCert = certAuth.SignAndSerialize(certInfo, "demo-user@demo-server")
```

Enjoy the demo! 🚀
