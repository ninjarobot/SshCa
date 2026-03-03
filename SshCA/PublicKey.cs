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
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace SshCA;

/// <summary>
/// Represents a public key used in cryptographic algorithms.
/// The <c>PublicKey</c> type includes properties and methods necessary for creating, managing,
/// and converting public keys for SSH and other use cases.
/// </summary>
public abstract class PublicKey
{
    /// <summary>Initializes the base public key with an algorithm name and optional comment.</summary>
    protected PublicKey(string algorithm, string? comment)
    {
        Algorithm = algorithm;
        Comment = comment;
    }

    /// <summary>Identifies the algorithm type (e.g., "ssh-rsa").</summary>
    public string Algorithm { get; }

    /// <summary>An optional comment associated with the public key.</summary>
    public string? Comment { get; }

    /// <summary>Writes components of the public key to an SshBuffer for serialization.</summary>
    public abstract void WritePublicKeyComponents(SshBuffer sshBuf);

    /// <summary>
    /// Converts a <c>PublicKey</c> instance into a byte array formatted according to the SSH public key standard.
    /// </summary>
    public byte[] AsSshPublicKeyBytes
    {
        get
        {
            using var ms = new MemoryStream();
            var sshBuf = new SshBuffer(ms);
            sshBuf.WriteSshData(Encoding.UTF8.GetBytes(Algorithm));
            WritePublicKeyComponents(sshBuf);
            return ms.ToArray();
        }
    }

    /// <summary>
    /// Converts a <c>PublicKey</c> instance into its SSH public key string representation.
    /// The output format is: <c>&lt;algorithm&gt; &lt;base64-key-bytes&gt; [optional-comment]</c>.
    /// </summary>
    public string AsSshPublicKey
    {
        get
        {
            var pkBytes = AsSshPublicKeyBytes;
            if (string.IsNullOrWhiteSpace(Comment))
                return string.Format("{0} {1}", Algorithm, Convert.ToBase64String(pkBytes));
            else
                return string.Format("{0} {1} {2}", Algorithm, Convert.ToBase64String(pkBytes), Comment);
        }
    }

    /// <inheritdoc/>
    public override string ToString() => AsSshPublicKey;

    /// <summary>
    /// Parses an SSH public key from its string representation.
    /// </summary>
    /// <param name="keyLine">A string in the form <c>&lt;algorithm&gt; &lt;base64-key-data&gt; [optional-comment]</c>.</param>
    /// <returns>A <see cref="RsaPublicKey"/> initialized with the parsed key data and optional comment.</returns>
    /// <exception cref="FormatException">Thrown when the key string is not properly formatted.</exception>
    public static RsaPublicKey OfSshPublicKey(string keyLine)
    {
        if (string.IsNullOrEmpty(keyLine))
            throw new ArgumentException("Empty OpenSSH public key passed.", nameof(keyLine));
        // Plain SSH key line is ~400 characters, so 10,000 is a sane maximum.
        if (keyLine.Length > 10_000)
            throw new FormatException("Oversized OpenSSH public key line");
        var sections = keyLine.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
        if (sections.Length > 1)
        {
            var b64data = sections[1];
            var data = Convert.FromBase64String(b64data);
            using var ms = new MemoryStream(data);
            var sshBuf = new SshBuffer(ms);
            _ = sshBuf.ReadSshData(); // algorithm name (already in sections[0])
            var e = sshBuf.ReadSshData();
            var n = sshBuf.ReadSshData();
            if (sections.Length > 2)
                return new RsaPublicKey(e, n, string.Join(' ', sections[2..]));
            else
                return new RsaPublicKey(e, n);
        }
        throw new FormatException("Malformed OpenSSH public key line.");
    }

    /// <summary>
    /// Converts a <c>PublicKey</c> instance into its SSH public key string representation.
    /// </summary>
    public static string ToSshPublicKey(PublicKey pubKey) => pubKey.AsSshPublicKey;

    /// <summary>
    /// Converts a <c>PublicKey</c> instance into a <c>cert-authority</c> line ready for adding to an
    /// <c>authorized_keys</c> file.
    /// </summary>
    public static string ToSshCertAuthority(PublicKey pubKey) =>
        string.Concat("cert-authority ", pubKey.AsSshPublicKey);

    /// <summary>
    /// Converts a PEM-encoded RSA public key string and a comment to an internal representation
    /// suitable for working with SSH-compatible RSA parameters.
    /// </summary>
    /// <param name="pem">The PEM-encoded RSA public key string.</param>
    /// <param name="comment">An optional comment field.</param>
    public static RsaPublicKey OfRsaPublicKeyPem(string pem, string? comment)
    {
        if (string.IsNullOrEmpty(pem))
            throw new ArgumentException("Empty RSA public key PEM passed.", nameof(pem));
        using var rsa = RSA.Create();
        rsa.ImportFromPem(pem);
        var exported = rsa.ExportParameters(false);
        // RSA can generate a modulus with MSB set (so negative) but openssh doesn't like this.
        // It does allow a prepended '\0' (NULL) that will force the MSB to be positive. It then trims this
        // NULL so it becomes the same modulus as before. Using that same technique here.
        byte[] forcePosMod;
        if ((exported.Modulus![0] & 128) != 0)
        {
            forcePosMod = new byte[exported.Modulus.Length + 1];
            exported.Modulus.CopyTo(forcePosMod, 1);
        }
        else
        {
            forcePosMod = exported.Modulus;
        }
        return new RsaPublicKey(exported.Exponent!, forcePosMod, comment);
    }

    /// <summary>
    /// Converts a PEM-encoded RSA public key string to an internal representation
    /// suitable for working with SSH-compatible RSA parameters.
    /// </summary>
    /// <param name="pem">The PEM-encoded RSA public key string.</param>
    public static RsaPublicKey OfRsaPublicKeyPem(string pem) => OfRsaPublicKeyPem(pem, null);

    /// <summary>
    /// Converts a <c>PublicKey</c> to an RSA public key represented as an <see cref="RSA"/> object.
    /// Be sure to dispose of this RSA instance after use.
    /// </summary>
    public static RSA ToRsaPublicKey(PublicKey pubKey)
    {
        if (pubKey is RsaPublicKey rsaPublicKey)
            return RSA.Create(new RSAParameters { Exponent = rsaPublicKey.Exponent, Modulus = rsaPublicKey.Modulus });
        throw new InvalidOperationException(string.Format("Cannot convert {0} public key to RSA.", pubKey.Algorithm));
    }
}

/// <summary>
/// Represents an SSH RSA public key with exponent, modulus, and optional comment.
/// </summary>
public sealed class RsaPublicKey : PublicKey, IEquatable<RsaPublicKey>
{
    /// <summary>The SSH algorithm identifier for RSA keys.</summary>
    public static readonly string SshRsa = "ssh-rsa";

    /// <summary>Initializes a new <see cref="RsaPublicKey"/> with exponent, modulus, and comment.</summary>
    public RsaPublicKey(byte[] exponent, byte[] modulus, string? comment)
        : base(SshRsa, comment)
    {
        Exponent = exponent;
        Modulus = modulus;
    }

    /// <summary>Initializes a new <see cref="RsaPublicKey"/> with exponent and modulus.</summary>
    public RsaPublicKey(byte[] exponent, byte[] modulus)
        : this(exponent, modulus, null)
    {
    }

    /// <summary>The public exponent of the RSA key.</summary>
    public byte[] Exponent { get; }

    /// <summary>The modulus of the RSA key.</summary>
    public byte[] Modulus { get; }

    /// <inheritdoc/>
    public override void WritePublicKeyComponents(SshBuffer sshBuf)
    {
        sshBuf.WriteSshData(Exponent);
        sshBuf.WriteSshData(Modulus);
    }

    /// <inheritdoc/>
    public bool Equals(RsaPublicKey? other)
    {
        if (other is null) return false;
        return Algorithm == other.Algorithm &&
               System.Collections.StructuralComparisons.StructuralEqualityComparer.Equals(Exponent, other.Exponent) &&
               System.Collections.StructuralComparisons.StructuralEqualityComparer.Equals(Modulus, other.Modulus) &&
               Comment == other.Comment;
    }

    /// <inheritdoc/>
    public override bool Equals(object? obj)
    {
        if (ReferenceEquals(this, obj)) return true;
        return obj is RsaPublicKey other && Equals(other);
    }

    /// <inheritdoc/>
    public override int GetHashCode() =>
        HashCode.Combine(
            SshRsa,
            ((System.Collections.IStructuralEquatable)Exponent).GetHashCode(System.Collections.Generic.EqualityComparer<byte>.Default),
            ((System.Collections.IStructuralEquatable)Modulus).GetHashCode(System.Collections.Generic.EqualityComparer<byte>.Default),
            Comment);
}
