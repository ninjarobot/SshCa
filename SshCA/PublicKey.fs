namespace SshCA

open System
open System.IO
open System.Security.Cryptography
open System.Text
open SshBuffer

type PublicKey =
    {
        Algorithm: string
        Exponent: byte array
        Modulus: byte array
        Comment: string option
    }

module PublicKey =
    [<Literal>]
    let SshRsa = "ssh-rsa"

    let ofSshPublicKey (keyLine:string) =
        let sections = keyLine.Split ([|' ';'\t'|], StringSplitOptions.RemoveEmptyEntries)
        if sections.Length > 1 then
            let algName = sections[0]
            let b64data = sections[1]
            let data = b64data |> Convert.FromBase64String
            use ms = new MemoryStream(data)
            let alg = readSshBuf ms
            let e = readSshBuf ms
            let n = readSshBuf ms
            let comment = 
                if sections.Length > 2 then sections[2] |> Some
                else None
            {
                Algorithm = alg |> Encoding.UTF8.GetString
                Exponent = e
                Modulus = n
                Comment = comment
            }
        else
            failwith "Malformed key line"

    /// Converts a `PublicKey` instance into a byte array formatted according to the SSH public key standard.
    ///
    /// The function writes the `Algorithm` string, `Exponent`, and `Modulus` of the `PublicKey` instance
    /// into a `MemoryStream` in the required SSH buffer format, and then retrieves the resulting byte array.
    ///
    /// Parameters:
    ///   pubKey: The `PublicKey` instance containing the algorithm, exponent, and modulus fields to be formatted.
    ///
    /// Returns:
    ///   A byte array representing the SSH public key in the required format.
    let toSshPublicKeyBytes (pubKey:PublicKey) =
        using (new MemoryStream()) (fun ms ->
            pubKey.Algorithm |> (Encoding.UTF8.GetBytes >> appendSshBuf ms)
            pubKey.Exponent |> appendSshBuf ms
            pubKey.Modulus |> appendSshBuf ms
            ms.ToArray()
        )

    /// Converts a `PublicKey` instance into its SSH public key string representation.
    ///
    /// The output format adheres to the standard OpenSSH format:
    /// `<algorithm> <base64-encoded-key-bytes> <optional-comment>`.
    ///
    /// Parameters:
    ///   pubKey: The `PublicKey` instance containing the algorithm, exponent, modulus, and optional comment.
    ///
    /// Returns:
    ///   A string in the SSH public key format.
    let toSshPublicKey (pubKey:PublicKey) =
        let pkBytes = toSshPublicKeyBytes pubKey
        String.Format(
            "{0} {1} {2}",
            pubKey.Algorithm,
            (Convert.ToBase64String pkBytes),
            pubKey.Comment |> Option.defaultValue ""
        )

    /// Converts a PEM-encoded RSA public key string to an internal representation
    /// suitable for working with SSH-compatible RSA parameters.
    ///
    /// The function imports the RSA public key from a PEM-encoded string, extracts
    /// the parameters such as modulus and exponent, and applies a technique to
    /// ensure the modulus is properly formatted for OpenSSH compatibility. Specifically,
    /// it ensures the most significant bit (MSB) of the modulus is positive.
    ///
    /// Returns a record containing:
    /// - Algorithm: Identifies the algorithm type (e.g., RSA).
    /// - Exponent: The public exponent of the RSA key.
    /// - Modulus: The modulus of the RSA key, adjusted to a positive MSB if required.
    /// - Comment: An optional comment field, which defaults to None.
    let ofRsaPublicKeyPem (pem:string) =
        use rsa = RSA.Create()
        rsa.ImportFromPem(pem)
        let exported = rsa.ExportParameters(false)
        // RSA can generate a modulus with MSB set (so negative) but openssh doesn't like this.
        // It does allow a prepended '\0' (NULL) that will force the MSB to be positive. It then trims this
        // NULL so it becomes the same modulus as before. Using that same technique here.
        let forcePosMod =
            seq {
                0uy
                yield! exported.Modulus
            } |> Array.ofSeq
        {
            Algorithm = SshRsa
            Exponent = exported.Exponent
            Modulus = forcePosMod
            Comment = None
        }

    /// Converts a `PublicKey` to an RSA public key represented as an `RSA` object.
    /// This function uses the `Exponent` and `Modulus` properties of the given `PublicKey`
    /// to create an `RSAParameters` structure, which is then used to initialize the RSA instance.
    ///
    /// Be sure to dispose of this RSA instance after use.
    ///
    /// Parameters:
    ///   pubKey: The `PublicKey` instance containing the RSA exponent and modulus.
    ///
    /// Returns:
    ///   An `RSA` object initialized with the specified public key parameters.
    let toRsaPublicKey (pubKey:PublicKey) =
        RSA.Create(RSAParameters(Exponent=pubKey.Exponent, Modulus=pubKey.Modulus))
