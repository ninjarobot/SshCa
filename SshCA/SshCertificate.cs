using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;

namespace SshCA
{
    public class CertificateInfo
    {
        public byte[] Nonce { get; set; }
        public PublicKey PublicKeyToSign { get; }
        public ulong Serial { get; set; } = 0UL;
        public string KeyId { get; set; }
        public IEnumerable<string> Principals { get; set; } = Array.Empty<string>();
        public DateTimeOffset ValidAfter { get; set; } = DateTimeOffset.MinValue;
        public DateTimeOffset ValidBefore { get; set; } = DateTimeOffset.MinValue;
        public IEnumerable<string> CriticalOptions { get; set; } = Array.Empty<string>();
        public IEnumerable<string> Extensions { get; set; } = Array.Empty<string>();
        public PublicKey CaPublicKey { get; }

        public CertificateInfo(string keyId, PublicKey publicKeyToSign, PublicKey caPublicKey, byte[] nonce)
        {
            KeyId = keyId ?? throw new ArgumentNullException(nameof(keyId));
            PublicKeyToSign = publicKeyToSign ?? throw new ArgumentNullException(nameof(publicKeyToSign));
            CaPublicKey = caPublicKey ?? throw new ArgumentNullException(nameof(caPublicKey));
            Nonce = nonce ?? throw new ArgumentNullException(nameof(nonce));
        }

        public CertificateInfo(string keyId, PublicKey publicKeyToSign, PublicKey caPublicKey)
            : this(keyId, publicKeyToSign, caPublicKey, RandomNumberGenerator.GetBytes(32)) { }
    }

    public class CertificateAuthority
    {
        private readonly Func<Stream, byte[]> _signData;

        public CertificateAuthority(Func<Stream, byte[]> signData)
        {
            _signData = signData ?? throw new ArgumentNullException(nameof(signData));
        }

        private const uint SSH2_CERT_TYPE_USER = 1u;

        private static byte[] StringsToBuffer(IEnumerable<string>? s)
        {
            using var ms = new MemoryStream();
            var sshBuf = new SshBuffer(ms);
            if (s is not null)
            {
                foreach (var str in s)
                {
                    sshBuf.AppendSshBuf(str);
                }
            }
            return ms.ToArray();
        }

        private static MemoryStream BuildCertificateContentStream(CertificateInfo certInfo)
        {
            var keyType = SSH2_CERT_TYPE_USER;

            // Empty string for now (this is a size of 0).
            var reserved = BitConverter.GetBytes(0u);

            // https://www.ietf.org/proceedings/122/slides/slides-122-sshm-openssh-certificate-format-00.pdf
            var certMs = new MemoryStream();
            var certSshBuf = new SshBuffer(certMs);
            certSshBuf.AppendSshBuf("ssh-rsa-cert-v01@openssh.com");
            certSshBuf.AppendSshBuf(certInfo.Nonce);
            certSshBuf.AppendSshBuf(certInfo.PublicKeyToSign.Exponent);
            certSshBuf.AppendSshBuf(certInfo.PublicKeyToSign.Modulus);
            certSshBuf.AppendSshBuf(certInfo.Serial);
            certSshBuf.AppendSshBuf(keyType);
            certSshBuf.AppendSshBuf(certInfo.KeyId);
            certSshBuf.AppendSshBuf(StringsToBuffer(certInfo.Principals));
            certSshBuf.AppendSshBuf(certInfo.ValidAfter.ToUnixTimeSeconds());
            certSshBuf.AppendSshBuf(certInfo.ValidBefore.ToUnixTimeSeconds());
            certSshBuf.AppendSshBuf(StringsToBuffer(certInfo.CriticalOptions));
            certSshBuf.AppendSshBuf(StringsToBuffer(certInfo.Extensions));
            certSshBuf.AppendSshBufRaw(reserved);
            certSshBuf.AppendSshBuf(PublicKey.ToSshPublicKeyBytes(certInfo.CaPublicKey));
            return certMs;
        }

        private static byte[] Sign(Func<Stream, byte[]> signData, MemoryStream certContents)
        {
            using var dataToSign = new MemoryStream();
            certContents.Position = 0L;
            certContents.CopyTo(dataToSign);
            dataToSign.Position = 0;
            return signData(dataToSign);
        }

        private static void AppendSignature(Stream certContents, byte[] signature)
        {
            using var ms = new MemoryStream();
            var sshBuf = new SshBuffer(ms);
            sshBuf.AppendSshBuf("rsa-sha2-512");
            sshBuf.AppendSshBuf(signature);
            // Append the whole thing as a string for the signature blob
            new SshBuffer(certContents).AppendSshBuf(ms.ToArray());
        }

        public byte[] Sign(CertificateInfo certInfo)
        {
            if (certInfo is null) throw new ArgumentNullException(nameof(certInfo));
            if (certInfo.Nonce.Length != 32)
                throw new InvalidOperationException("Nonce must be 32 bytes.");

            using var ms = BuildCertificateContentStream(certInfo);
            var sig = Sign(_signData, ms);
            AppendSignature(ms, sig);
            return ms.ToArray();
        }

        public string SignAndSerialize(CertificateInfo certInfo, string comment)
        {
            var certBytes = Sign(certInfo);
            var b64Cert = Convert.ToBase64String(certBytes);
            if (string.IsNullOrWhiteSpace(comment))
            {
                return string.Format("ssh-rsa-cert-v01@openssh.com {0}", b64Cert);
            }
            else
            {
                return string.Format("ssh-rsa-cert-v01@openssh.com {0} {1}", b64Cert, comment);
            }
        }
    }
}
