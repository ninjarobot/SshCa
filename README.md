SshCA
=====

[![Build and Test](https://github.com/ninjarobot/SshCa/actions/workflows/build-and-test.yml/badge.svg)](https://github.com/ninjarobot/SshCa/actions/workflows/build-and-test.yml)
[![SshCa on Nuget](https://img.shields.io/nuget/v/SshCA)](https://www.nuget.org/packages/SshCA/)

Use SSH public key and and CA certificates to sign SSH public keys. It can be used to read and write SSH public keys, convert between dotnet RSA public keys and the OpenSSH format, and to sign OpenSSH public keys in the format used by OpenSSH.

## 🚀 Try the Interactive Demo!

Want to see SshCA in action? Check out the [SshCaDemo](SshCaDemo) project - a catchy, interactive demo that shows you how to sign SSH keys step-by-step with beautiful output! Just run:

```bash
cd SshCaDemo
dotnet run
```

See the [SshCATests](SshCATests) project for additional examples.

### Features
* Read OpenSSH public keys and convert them to RSA public keys
* Read RSA public keys from a PEM file for use with signing.
* Write RSA public keys as OpenSSH public keys
* Sign OpenSSH public keys with an RSA implementation such as `System.Security.Cryptography.RSA` or the one returned by `Azure.Security.KeyVault.Keys.Cryptography.CryptographyClient.CreateRSA`.

### Important Information

* Conversion between RSA and OpenSSH public keys always formats them as `ssh-rsa`.
* Certificates need to be signed with SHA-512 as the signatures are always formatted as `rsa-sha2-512`.
* Generated certificate algorithm is always `rsa-sha2-512-cert-v01@openssh.com`.


The goal is to allow external service to sign SSH keys, so this gives some flexibility in what RSA implementation is
used for signing (dotnet RSA, OpenSSL, external call to Azure Key Vault or AWS KMS, maybe you have an HSM). Whichever
implementation is used, it should be signed with an RSA private key using SHA-512.

Support for signing elliptic curve keys is possible in OpenSSH, but not implemented at this time.

### Usage

This example uses an RSA key in Azure Key Vault to sign an SSH public key.
```csharp
using SshCA;
using System.IO;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Keys.Cryptography;
using System.Security.Cryptography;

// Read your existing SSH public key
var mySshPubKey =
    File.ReadAllText(
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            ".ssh",
            "id_rsa.pub"
        )
    );
var pubKey = PublicKey.OfSshPublicKey(mySshPubKey);

// Get the CA public key from Azure Key Vault
var cred = new Azure.Identity.DefaultAzureCredential();
var keyClient = new KeyClient(new Uri("https://mykeyvault.vault.azure.net"), cred);
var caRsaPubKey = keyClient.GetKey("ssh-signing-key");

// Convert the CA public key to OpenSSH format.
SshCA.PublicKey caPubKey = null;
string caPubKeySsh = null;
using (var rsa = caRsaPubKey.Value.Key.ToRSA()) {
    var caPubKeyPem = rsa.ExportRSAPublicKeyPem();
    caPubKey = SshCA.PublicKey.OfRsaPublicKeyPem(caPubKeyPem);
    caPubKeySsh = SshCA.PublicKey.ToSshPublicKey(caPubKey);
}
// Note: the OpenSSH formatted key `caPubKeySsh` should be added to a file and
// that file's path set in the TrustedUserCAKeys in your sshd_config. Or you can
// generate a cert-authority line to add to an individual authorized_keys file.

var certAuthLine = PublicKey.ToSshCertAuthority(caPubKey);

// Create certificate information. The key_id is going to show in the SSH logs when you use this certificate.
var certInfo = new CertificateInfo("my-account@linux-server", pubKey, caPubKey);
certInfo.ValidAfter = DateTimeOffset.Now;
certInfo.ValidBefore = certInfo.ValidAfter.AddHours(1); // This signature is only good for an hour.
certInfo.Principals = new List<string>() {"linuxuser"}; // Whatever user(s) you can login as.
certInfo.Extensions = new List<string>() {"permit-pty", ""}; // At least this so you can get a shell.

// Sign it using the CA private key. This signing happens in the Key Vault itself.
var cryptoClient = new CryptographyClient(new Uri("https://mykeyvault.vault.azure.net/keys/ssh-signing-key"), cred);

String signedCert = null;
using(var rsa = cryptoClient.CreateRSA()) {
    // Certificates must be signed with SHA-512.
    var certAuth = new CertificateAuthority(ms => rsa.SignData(ms, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1));
    var signedCert = certAuth.SignAndSerialize(certInfo, "comment-such-as:my-account@linux-server");    
}

// Write it out and it's ready to use.
File.WriteAllText(
    Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
        ".ssh",
        "id_rsa-cert.pub"
    ),
    signedCert
);
```