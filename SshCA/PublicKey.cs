using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace SshCA
{
    public class PublicKey
    {
        private const string SshRsa = "ssh-rsa";

        public string Algorithm { get; }
        public byte[] Exponent { get; }
        public byte[] Modulus { get; }
        public string? Comment { get; }

        public PublicKey(string algorithm, byte[] exponent, byte[] modulus, string? comment)
        {
            Algorithm = algorithm ?? throw new ArgumentNullException(nameof(algorithm));
            Exponent = exponent ?? throw new ArgumentNullException(nameof(exponent));
            Modulus = modulus ?? throw new ArgumentNullException(nameof(modulus));
            Comment = comment;
        }

        public PublicKey(string algorithm, byte[] exponent, byte[] modulus)
            : this(algorithm, exponent, modulus, null) { }

        public static PublicKey OfSshPublicKey(string keyLine)
        {
            if (keyLine is null) throw new ArgumentNullException(nameof(keyLine));
            var sections = keyLine.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
            if (sections.Length <= 1)
                throw new InvalidOperationException("Malformed key line");

            var b64data = sections[1];
            var data = Convert.FromBase64String(b64data);
            using var ms = new MemoryStream(data);
            var sshBuf = new SshBuffer(ms);
            var alg = Encoding.UTF8.GetString(sshBuf.ReadSshBuf());
            var e = sshBuf.ReadSshBuf();
            var n = sshBuf.ReadSshBuf();

            if (sections.Length > 2)
                return new PublicKey(alg, e, n, sections[2]);
            else
                return new PublicKey(alg, e, n);
        }

        public static byte[] ToSshPublicKeyBytes(PublicKey pubKey)
        {
            if (pubKey is null) throw new ArgumentNullException(nameof(pubKey));
            using var ms = new MemoryStream();
            var sshBuf = new SshBuffer(ms);
            sshBuf.AppendSshBuf(pubKey.Algorithm);
            sshBuf.AppendSshBuf(pubKey.Exponent);
            sshBuf.AppendSshBuf(pubKey.Modulus);
            return ms.ToArray();
        }

        public static string ToSshPublicKey(PublicKey pubKey)
        {
            var pkBytes = ToSshPublicKeyBytes(pubKey);
            if (string.IsNullOrWhiteSpace(pubKey.Comment))
                return string.Format("{0} {1}", pubKey.Algorithm, Convert.ToBase64String(pkBytes));
            else
                return string.Format("{0} {1} {2}", pubKey.Algorithm, Convert.ToBase64String(pkBytes), pubKey.Comment);
        }

        public static PublicKey OfRsaPublicKeyPem(string pem)
        {
            if (pem is null) throw new ArgumentNullException(nameof(pem));
            using var rsa = RSA.Create();
            rsa.ImportFromPem(pem);
            var exported = rsa.ExportParameters(false);

            // Ensure positive MSB for OpenSSH by prefixing a zero byte.
            var forcePosMod = new byte[exported.Modulus.Length + 1];
            // 0 byte already default; copy original modulus starting at index 1
            Buffer.BlockCopy(exported.Modulus, 0, forcePosMod, 1, exported.Modulus.Length);

            return new PublicKey(SshRsa, exported.Exponent!, forcePosMod);
        }

        public static RSA ToRsaPublicKey(PublicKey pubKey)
        {
            if (pubKey is null) throw new ArgumentNullException(nameof(pubKey));
            var rsa = RSA.Create();
            rsa.ImportParameters(new RSAParameters
            {
                Exponent = pubKey.Exponent,
                Modulus = pubKey.Modulus
            });
            return rsa;
        }
    }
}
