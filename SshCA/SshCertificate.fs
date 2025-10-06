namespace SshCA

open System
open System.IO
open System.Security.Cryptography

[<AllowNullLiteral>]
type CertificateInfo(keyId:string, publicKeyToSign:PublicKey, caPublicKey:PublicKey, nonce:byte array) =
    member val Nonce = nonce with get, set
    member val PublicKeyToSign = publicKeyToSign with get
    member val Serial = 0UL with get, set
    member val KeyId = keyId with get, set
    member val Principals = Seq.empty<string> with get, set
    member val ValidAfter = DateTimeOffset.MinValue with get, set
    member val ValidBefore = DateTimeOffset.MinValue with get, set
    member val CriticalOptions = Seq.empty<string> with get, set
    member val Extensions = Seq.empty<string> with get, set
    member val CaPublicKey = caPublicKey with get

    new (keyId:string, publicKeyToSign:PublicKey, caPublicKey:PublicKey) =
        CertificateInfo(keyId, publicKeyToSign, caPublicKey, RandomNumberGenerator.GetBytes 32)

[<Sealed>]
type CertificateAuthority(signData:Func<Stream, byte array>) =

    /// User certificate is 1u: https://github.com/openssh/openssh-portable/blob/edc601707b583a2c900e49621e048c26574edd3a/ssh2.h#L179
    [<Literal>]
    static let SSH2_CERT_TYPE_USER = 1u

    /// Writes a sequence of strings to a new buffer and returns the data.
    static let stringsToBuffer (s:string seq) =
        use ms = new MemoryStream()
        let sshBuf = SshBuffer(ms)
        if not <| isNull s then
            s |> Seq.iter sshBuf.WriteSshString
        ms.ToArray()

    /// Builds the certificate contents ready to sign in a MemoryStream.
    static let buildCertificateContentStream (certInfo:CertificateInfo) =
        let keyType = SSH2_CERT_TYPE_USER
        
        let reserved = 0u |> BitConverter.GetBytes // Empty string for now (this is a size of 0).
        
        // Super helpful presentation explaining these fields:
        // https://www.ietf.org/proceedings/122/slides/slides-122-sshm-openssh-certificate-format-00.pdf
        let certMs = new MemoryStream()
        let certSshBuf = SshBuffer(certMs)
        "ssh-rsa-cert-v01@openssh.com" |> certSshBuf.WriteSshString
        certInfo.Nonce |> certSshBuf.WriteSshData
        certInfo.PublicKeyToSign.WritePublicKeyComponents certSshBuf
        certInfo.Serial |> certSshBuf.WriteSshData
        keyType |> certSshBuf.WriteSshData
        certInfo.KeyId |> certSshBuf.WriteSshString
        certInfo.Principals |> stringsToBuffer |> certSshBuf.WriteSshData
        certInfo.ValidAfter.ToUnixTimeSeconds() |> certSshBuf.WriteSshData
        certInfo.ValidBefore.ToUnixTimeSeconds() |> certSshBuf.WriteSshData
        certInfo.CriticalOptions |> stringsToBuffer |> certSshBuf.WriteSshData
        certInfo.Extensions |> stringsToBuffer |> certSshBuf.WriteSshData
        reserved |> certSshBuf.WriteSshData
        certInfo.CaPublicKey.AsSshPublicKeyBytes |> certSshBuf.WriteSshData
        certMs

    /// Signs the certificate content and returns that signature. The memory stream containing
    /// the certificate content will be at the same position after signing.
    static let sign (signData:Stream -> byte array) (certContents:MemoryStream) =
        use dataToSign = new MemoryStream()
        certContents.Position <- 0L
        certContents.CopyTo(dataToSign)
        // Have to set the position to the beginning before signing or it will produce and invalid signature.
        dataToSign.Position <- 0
        dataToSign |> signData

    /// Appends the signature to the certificate content stream.
    static let appendSignature (certContents:Stream) (signature:byte array) =
        use ms = new MemoryStream()
        let sshBuf = SshBuffer(ms)
        "rsa-sha2-512" |> sshBuf.WriteSshString
        signature |> sshBuf.WriteSshData
        // Append the whole thing as a string for the signature blob
        ms.ToArray() |> SshBuffer(certContents).WriteSshData

    /// Writes the certificate contents to a byte array.
    static let getCertificateBytes(certContents:MemoryStream) =
        certContents.ToArray()

    /// Builds and signs and SSH certificate, returning the certificate contents.
    member _.Sign(certInfo:CertificateInfo) =
        if isNull certInfo then
            nullArg "certInfo"
        if certInfo.Nonce.Length <> 32 then
            invalidArg "certInfo.Nonce" "Nonce must be 32 bytes."
        use ms = buildCertificateContentStream(certInfo)
        ms
        |> sign signData.Invoke
        |> appendSignature ms
        getCertificateBytes ms

    /// Builds and signs an SSH certificate, returning the contents in OpenSSH serialized format.
    member this.SignAndSerialize (certInfo:CertificateInfo, comment:string) =
        if isNull certInfo then
            nullArg "certInfo"
        let certBytes = certInfo |> this.Sign
        let b64Cert = certBytes |> Convert.ToBase64String
        if String.IsNullOrWhiteSpace comment then
            String.Format("ssh-rsa-cert-v01@openssh.com {0}", b64Cert)
        else
            String.Format("ssh-rsa-cert-v01@openssh.com {0} {1}", b64Cert, comment)
