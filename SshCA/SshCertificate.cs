/*
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
*/
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace SshCA;

/// <summary>
/// Holds the information needed to build and sign an SSH certificate.
/// </summary>
public class CertificateInfo
{
    /// <summary>
    /// Initializes a new <see cref="CertificateInfo"/> with a key ID, the public key to sign,
    /// a CA public key, and an explicit nonce.
    /// </summary>
    public CertificateInfo(string keyId, PublicKey publicKeyToSign, PublicKey caPublicKey, byte[] nonce)
    {
        KeyId = keyId;
        PublicKeyToSign = publicKeyToSign;
        CaPublicKey = caPublicKey;
        Nonce = nonce;
    }

    /// <summary>
    /// Initializes a new <see cref="CertificateInfo"/> with a key ID, the public key to sign,
    /// and a CA public key. A 32-byte random nonce is generated automatically.
    /// </summary>
    public CertificateInfo(string keyId, PublicKey publicKeyToSign, PublicKey caPublicKey)
        : this(keyId, publicKeyToSign, caPublicKey, RandomNumberGenerator.GetBytes(32))
    {
    }

    /// <summary>Gets or sets the 32-byte nonce used when building the certificate.</summary>
    public byte[] Nonce { get; set; }

    /// <summary>Gets the public key to be signed by this certificate.</summary>
    public PublicKey PublicKeyToSign { get; }

    /// <summary>Gets or sets the certificate serial number.</summary>
    public ulong Serial { get; set; }

    /// <summary>Gets or sets the key identifier string embedded in the certificate.</summary>
    public string KeyId { get; set; }

    /// <summary>Gets or sets the list of principals (user names) authorized by the certificate.</summary>
    public IEnumerable<string> Principals { get; set; } = Array.Empty<string>();

    /// <summary>Gets or sets the earliest time from which the certificate is valid.</summary>
    public DateTimeOffset ValidAfter { get; set; } = DateTimeOffset.MinValue;

    /// <summary>Gets or sets the latest time until which the certificate is valid.</summary>
    public DateTimeOffset ValidBefore { get; set; } = DateTimeOffset.MinValue;

    /// <summary>Gets or sets the critical options embedded in the certificate.</summary>
    public IEnumerable<string> CriticalOptions { get; set; } = Array.Empty<string>();

    /// <summary>Gets or sets the extensions embedded in the certificate.</summary>
    public IEnumerable<string> Extensions { get; set; } = Array.Empty<string>();

    /// <summary>Gets the CA public key used to sign this certificate.</summary>
    public PublicKey CaPublicKey { get; }
}

internal static class CertificateSigning
{
    /// <summary>User certificate type: https://github.com/openssh/openssh-portable/blob/edc601707b583a2c900e49621e048c26574edd3a/ssh2.h#L179</summary>
    internal const uint SSH2_CERT_TYPE_USER = 1u;

    /// <summary>Certificate signing algorithm is SHA-512.</summary>
    internal const string RSA_SHA_512_CERT_ALG = "rsa-sha2-512-cert-v01@openssh.com";

    /// <summary>Writes a sequence of strings to a new buffer and returns the data.</summary>
    internal static byte[] StringsToBuffer(IEnumerable<string> s)
    {
        using var ms = new MemoryStream();
        var sshBuf = new SshBuffer(ms);
        if (s != null)
        {
            foreach (var item in s)
                sshBuf.WriteSshString(item);
        }
        return ms.ToArray();
    }

    /// <summary>Builds the certificate contents ready to sign in a MemoryStream.</summary>
    internal static MemoryStream BuildCertificateContentStream(CertificateInfo certInfo)
    {
        uint keyType = SSH2_CERT_TYPE_USER;

        var reserved = BitConverter.GetBytes(0u); // Empty string for now (this is a size of 0).

        // Super helpful presentation explaining these fields:
        // https://www.ietf.org/proceedings/122/slides/slides-122-sshm-openssh-certificate-format-00.pdf
        var certMs = new MemoryStream();
        var certSshBuf = new SshBuffer(certMs);
        certSshBuf.WriteSshString(RSA_SHA_512_CERT_ALG);
        certSshBuf.WriteSshData(certInfo.Nonce);
        certInfo.PublicKeyToSign.WritePublicKeyComponents(certSshBuf);
        certSshBuf.WriteSshData(certInfo.Serial);
        certSshBuf.WriteSshData(keyType);
        certSshBuf.WriteSshString(certInfo.KeyId);
        certSshBuf.WriteSshData(StringsToBuffer(certInfo.Principals));
        certSshBuf.WriteSshData(certInfo.ValidAfter.ToUnixTimeSeconds());
        certSshBuf.WriteSshData(certInfo.ValidBefore.ToUnixTimeSeconds());
        certSshBuf.WriteSshData(StringsToBuffer(certInfo.CriticalOptions));
        certSshBuf.WriteSshData(StringsToBuffer(certInfo.Extensions));
        certSshBuf.WriteSshData(reserved);
        certSshBuf.WriteSshData(certInfo.CaPublicKey.AsSshPublicKeyBytes);
        return certMs;
    }

    /// <summary>
    /// Signs the certificate content and returns that signature. The memory stream containing
    /// the certificate content will be at the same position after signing.
    /// </summary>
    internal static byte[] Sign(Func<Stream, byte[]> signData, MemoryStream certContents)
    {
        using var dataToSign = new MemoryStream();
        certContents.Position = 0L;
        certContents.CopyTo(dataToSign);
        // Have to set the position to the beginning before signing or it will produce an invalid signature.
        dataToSign.Position = 0;
        return signData(dataToSign);
    }

    internal static async Task<byte[]> SignAsync(
        Func<Stream, CancellationToken, Task<byte[]>> signData,
        CancellationToken cancellationToken,
        MemoryStream certContents)
    {
        using var dataToSign = new MemoryStream();
        certContents.Position = 0L;
        certContents.CopyTo(dataToSign);
        // Have to set the position to the beginning before signing or it will produce an invalid signature.
        dataToSign.Position = 0;
        return await signData(dataToSign, cancellationToken);
    }

    /// <summary>Appends the signature to the certificate content stream.</summary>
    internal static void AppendSignature(Stream certContents, byte[] signature)
    {
        using var ms = new MemoryStream();
        var sshBuf = new SshBuffer(ms);
        sshBuf.WriteSshString("rsa-sha2-512");
        sshBuf.WriteSshData(signature);
        // Append the whole thing as a string for the signature blob
        new SshBuffer(certContents).WriteSshData(ms.ToArray());
    }

    /// <summary>Writes the certificate contents to a byte array.</summary>
    internal static byte[] GetCertificateBytes(MemoryStream certContents) => certContents.ToArray();
}

/// <summary>
/// Signs SSH certificates using a synchronous signing function.
/// </summary>
public sealed class CertificateAuthority
{
    private readonly Func<Stream, byte[]> _signData;

    /// <summary>
    /// Initializes a new <see cref="CertificateAuthority"/> with the given signing function.
    /// </summary>
    /// <param name="signData">A function that signs a stream of data and returns the signature bytes.</param>
    public CertificateAuthority(Func<Stream, byte[]> signData) => _signData = signData;

    /// <summary>Builds and signs an SSH certificate, returning the certificate contents.</summary>
    public byte[] Sign(CertificateInfo certInfo)
    {
        if (certInfo is null)
            throw new ArgumentNullException("certInfo");
        if (certInfo.Nonce.Length != 32)
            throw new ArgumentException("Nonce must be 32 bytes.", "certInfo.Nonce");
        using var ms = CertificateSigning.BuildCertificateContentStream(certInfo);
        var signature = CertificateSigning.Sign(_signData, ms);
        CertificateSigning.AppendSignature(ms, signature);
        return CertificateSigning.GetCertificateBytes(ms);
    }

    /// <summary>Builds and signs an SSH certificate, returning the contents in OpenSSH serialized format.</summary>
    public string SignAndSerialize(CertificateInfo certInfo, string comment)
    {
        if (certInfo is null)
            throw new ArgumentNullException("certInfo");
        var certBytes = Sign(certInfo);
        var b64Cert = Convert.ToBase64String(certBytes);
        if (string.IsNullOrWhiteSpace(comment))
            return string.Format("{0} {1}", CertificateSigning.RSA_SHA_512_CERT_ALG, b64Cert);
        else
            return string.Format("{0} {1} {2}", CertificateSigning.RSA_SHA_512_CERT_ALG, b64Cert, comment);
    }
}

/// <summary>
/// Signs SSH certificates using an asynchronous signing function.
/// </summary>
public sealed class CertificateAuthorityAsync
{
    private readonly Func<Stream, CancellationToken, Task<byte[]>> _signDataAsync;

    /// <summary>
    /// Initializes a new <see cref="CertificateAuthorityAsync"/> with the given async signing function.
    /// </summary>
    public CertificateAuthorityAsync(Func<Stream, CancellationToken, Task<byte[]>> signDataAsync) =>
        _signDataAsync = signDataAsync;

    /// <summary>Builds and signs an SSH certificate asynchronously, returning the certificate contents.</summary>
    public async Task<byte[]> SignAsync(CertificateInfo certInfo, CancellationToken cancellationToken)
    {
        if (certInfo is null)
            throw new ArgumentNullException("certInfo");
        if (certInfo.Nonce.Length != 32)
            throw new ArgumentException("Nonce must be 32 bytes.", "certInfo.Nonce");
        using var ms = CertificateSigning.BuildCertificateContentStream(certInfo);
        var signature = await CertificateSigning.SignAsync(_signDataAsync, cancellationToken, ms);
        CertificateSigning.AppendSignature(ms, signature);
        return CertificateSigning.GetCertificateBytes(ms);
    }

    /// <summary>Builds and signs an SSH certificate asynchronously, returning the certificate contents.</summary>
    public Task<byte[]> SignAsync(CertificateInfo certInfo) =>
        SignAsync(certInfo, CancellationToken.None);

    /// <summary>
    /// Builds and signs an SSH certificate asynchronously, returning the contents in OpenSSH serialized format.
    /// </summary>
    public async Task<string> SignAndSerializeAsync(CertificateInfo certInfo, string comment)
    {
        if (certInfo is null)
            throw new ArgumentNullException("certInfo");
        var certBytes = await SignAsync(certInfo);
        var b64Cert = Convert.ToBase64String(certBytes);
        if (string.IsNullOrWhiteSpace(comment))
            return string.Format("{0} {1}", CertificateSigning.RSA_SHA_512_CERT_ALG, b64Cert);
        else
            return string.Format("{0} {1} {2}", CertificateSigning.RSA_SHA_512_CERT_ALG, b64Cert, comment);
    }
}
