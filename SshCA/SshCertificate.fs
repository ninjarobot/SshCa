namespace SshCA

open System
open System.IO
open System.Security.Cryptography
open System.Text
open SshBuffer
open PublicKey

module SshCertificate =

    /// User certificate is 1u: https://github.com/openssh/openssh-portable/blob/edc601707b583a2c900e49621e048c26574edd3a/ssh2.h#L179
    [<Literal>]
    let SSH2_CERT_TYPE_USER = 1u

    /// Each certificate has 32 random bytes of data that serve as a nonce to make this certificate fully unique
    let makeNonce () =
        RandomNumberGenerator.GetBytes 32

    /// Writes a sequence of strings to a new buffer and returns the data.
    let stringsToBuffer (s:string seq) =
        use ms = new MemoryStream()
        s |> Seq.iter (Encoding.UTF8.GetBytes >> appendSshBuf ms)
        ms.ToArray()

    /// Builds the certificate contents ready to sign in a MemoryStream.
    let buildCertificateContentStream
        (nonce:byte array option)
        (publicKeyToSign:PublicKey)
        (serial:uint64)
        (keyId:string)
        (principals:string seq)
        (validAfter:DateTimeOffset)
        (validBefore:DateTimeOffset)
        (criticalOptions:string seq)
        (extensions:string seq)
        (caPublicKey:PublicKey)
        =

        let keyType = SSH2_CERT_TYPE_USER
        
        let reserved = 0u |> BitConverter.GetBytes // Empty string for now (this is a size of 0).
        
        // Super helpful presentation explaining these fields:
        // https://www.ietf.org/proceedings/122/slides/slides-122-sshm-openssh-certificate-format-00.pdf
        let certMs = new MemoryStream()
        "ssh-rsa-cert-v01@openssh.com" |> Encoding.UTF8.GetBytes |> appendSshBuf certMs
        nonce |> Option.defaultWith makeNonce |> appendSshBuf certMs
        publicKeyToSign.Exponent |> appendSshBuf certMs
        publicKeyToSign.Modulus |> appendSshBuf certMs
        serial |> BitConverter.GetBytes |> Array.revIfLittleEndian |> certMs.Write // |> Array.rev |> certMs.Write
        keyType |> BitConverter.GetBytes |> Array.revIfLittleEndian |> certMs.Write
        keyId |> (System.Text.Encoding.UTF8.GetBytes >> appendSshBuf certMs)
        principals |> stringsToBuffer |> appendSshBuf certMs
        validAfter.ToUnixTimeSeconds() |> BitConverter.GetBytes |> Array.revIfLittleEndian |> certMs.Write
        validBefore.ToUnixTimeSeconds() |> BitConverter.GetBytes |> Array.revIfLittleEndian |> certMs.Write
        criticalOptions |> stringsToBuffer |> appendSshBuf certMs
        extensions |> stringsToBuffer |> appendSshBuf certMs
        reserved |> certMs.Write
        caPublicKey |> toSshPublicKeyBytes |> appendSshBuf certMs
        certMs

    /// Signs the certificate content and returns that signature. The memory stream containing
    /// the certificate content will be at the same position after signing.
    let sign (signData:MemoryStream -> byte array) (certContents:MemoryStream) =
        use dataToSign = new MemoryStream()
        certContents.Position <- 0L
        certContents.CopyTo(dataToSign)
        // Have to set the position to the beginning before signing or it will produce and invalid signature.
        dataToSign.Position <- 0
        //let data = dataToSign.ToArray()
        dataToSign |> signData

    /// Appends the signature to the certificate content stream.
    let appendSignature (certContents:Stream) (signature:byte array) =
        using (new MemoryStream()) (fun ms ->
            "rsa-sha2-512" |> (Encoding.UTF8.GetBytes >> appendSshBuf ms)
            signature |> appendSshBuf ms
            // Append the whole thing as a string for the signature blob
            ms.ToArray() |> appendSshBuf certContents
        )

    /// Writes the certificate contents to a byte array.
    let getCertificateBytes(certContents:MemoryStream) =
        certContents.ToArray()

    /// Writes the certificate to ssh format.
    let toSshFormat (comment:string) (certBytes:byte array) =
        let b64Cert = certBytes |> Convert.ToBase64String
        String.Format("ssh-rsa-cert-v01@openssh.com {0} {1}", b64Cert, comment).TrimEnd()
