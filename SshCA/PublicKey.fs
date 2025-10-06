namespace SshCA

open System
open System.IO
open System.Security.Cryptography
open System.Text

[<AbstractClass>]
type PublicKey(algorithm:string, comment:string) =
    /// Represents a public key used in cryptographic algorithms.
    ///
    /// The `PublicKey` type includes properties and methods necessary for creating, managing,
    /// and converting public keys for SSH and other use cases. It includes fields such as
    /// `Algorithm`, `Exponent`, `Modulus`, and an optional `Comment`.
    member val Algorithm: string = algorithm with get

    /// Represents a public key with associated metadata and functionality.
    ///
    /// A PublicKey contains properties such as the algorithm, key bytes, and an optional comment.
    /// It also provides methods to perform operations like converting the PublicKey instance into a format
    /// compatible with SSH public key representations.
    member val Comment: string = comment with get
    
    /// Writes components of the public key to an SshBuffer for serialization.
    abstract member WritePublicKeyComponents: SshBuffer -> unit
    
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
    member this.AsSshPublicKeyBytes =
        use ms = new MemoryStream()
        let sshBuf = SshBuffer(ms)
        this.Algorithm |> (Encoding.UTF8.GetBytes >> sshBuf.WriteSshData)
        this.WritePublicKeyComponents sshBuf
        ms.ToArray()

    member this.AsSshPublicKey =
        let pkBytes = this.AsSshPublicKeyBytes
        if String.IsNullOrWhiteSpace this.Comment then
            String.Format(
                "{0} {1}",
                this.Algorithm,
                Convert.ToBase64String pkBytes
            )
        else
            String.Format(
                "{0} {1} {2}",
                this.Algorithm,
                Convert.ToBase64String pkBytes,
                this.Comment
            )

    override this.ToString() =
        this.AsSshPublicKey

/// Represents a public key adhering to the SSH public key standard.
///
/// This type encapsulates properties and methods for handling and formatting
/// public key information, including the algorithm, public key components, and an
/// optional comment. It provides functionality for parsing keys from strings
/// and converting keys to their SSH public key representation.
type RsaPublicKey(exponent:byte array, modulus:byte array, comment:string) =
    inherit PublicKey(RsaPublicKey.SshRsa, comment)
    /// Represents the identifier for the RSA algorithm in the context
    /// of SSH public key operations. The value is a literal string
    /// "ssh-rsa", which is used to specify the RSA algorithm type in
    /// SSH key exchanges and related operations.
    static member SshRsa = "ssh-rsa"

    /// Represents the exponent value of a public RSA key as a byte array.
    ///
    /// The exponent is a critical component of the RSA public key used
    /// in cryptographic algorithms. This property provides read-only
    /// access to the exponent value stored in the `PublicKey` instance.
    member val Exponent: byte array = exponent with get

    /// The `Modulus` property represents the modulus component of a public key, stored as a byte array.
    /// This is a read-only property that returns the modulus, a critical part of the cryptographic
    /// public key used in various operations, including SSH key generation and RSA encryption.
    member val Modulus: byte array = modulus with get

    /// Represents an SSH public key with RSA algorithm and associated parameters.
    ///
    /// Properties:
    /// - Algorithm: Represents the type of the algorithm (e.g., "ssh-rsa").
    /// - Exponent: The public exponent of the RSA key.
    /// - Modulus: The modulus of the RSA key.
    /// - Comment: An optional comment associated with the public key.
    new(exponent, modulus) = RsaPublicKey(exponent, modulus, null)

    override this.WritePublicKeyComponents (sshBuf:SshBuffer) =
        this.Exponent |> sshBuf.WriteSshData
        this.Modulus |> sshBuf.WriteSshData

    interface IEquatable<RsaPublicKey> with
        member this.Equals (other: RsaPublicKey) =
            this.Algorithm = other.Algorithm &&
            System.Collections.StructuralComparisons.StructuralEqualityComparer.Equals(this.Exponent, other.Exponent) &&
            System.Collections.StructuralComparisons.StructuralEqualityComparer.Equals(this.Modulus, other.Modulus) &&
            this.Comment = other.Comment

    override this.Equals(other) =
        if Object.ReferenceEquals(this,other) then true
        else
            match other with
            | :? RsaPublicKey as otherPubKey ->
                (this :> IEquatable<RsaPublicKey>).Equals otherPubKey
            | _ -> false

    override this.GetHashCode() =
        HashCode.Combine(
            RsaPublicKey.SshRsa,
            (exponent :> System.Collections.IStructuralEquatable).GetHashCode(System.Collections.Generic.EqualityComparer<byte>.Default),
            (modulus :> System.Collections.IStructuralEquatable).GetHashCode(System.Collections.Generic.EqualityComparer<byte>.Default),
            comment)

type PublicKey with
    /// Parses an SSH public key from its string representation.
    ///
    /// This function processes a string representation of an SSH public key,
    /// extracting its algorithm name, base64-encoded key data, and an optional
    /// comment. It validates that the provided string format adheres to the SSH
    /// public key standard. If the string contains sufficient valid information,
    /// an instance of the `PublicKey` is returned.
    ///
    /// Parameters:
    /// - `keyLine`: A string representation of the SSH public key,
    ///   typically in the form `<algorithm> <base64-key-data> [optional-comment]`.
    ///
    /// Returns:
    /// - An instance of the `PublicKey` class initialized with the parsed key
    ///   data and optional comment.
    ///
    /// Exceptions:
    /// - `System.FormatException`: Thrown when the key string is not properly
    ///   formatted or when base64 decoding fails.
    /// - `System.InvalidOperationException`: Thrown when the parsed data does not
    ///   contain sufficient information to construct a valid public key.
    ///
    /// Assumptions:
    /// - The key string follows the standard SSH public key format.
    static member OfSshPublicKey (keyLine:string) =
        let sections = keyLine.Split ([|' ';'\t'|], StringSplitOptions.RemoveEmptyEntries)
        if sections.Length > 1 then
            let algName = sections[0]
            let b64data = sections[1]
            let data = b64data |> Convert.FromBase64String
            use ms = new MemoryStream(data)
            let sshBuf = SshBuffer(ms)
            let alg = sshBuf.ReadSshData() |> Encoding.UTF8.GetString
            let e = sshBuf.ReadSshData()
            let n = sshBuf.ReadSshData()
            if sections.Length > 2 then RsaPublicKey(e, n, sections[2]) // key comment.
            else RsaPublicKey(e, n)
        else
            failwith "Malformed key line"

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
    static member ToSshPublicKey (pubKey:RsaPublicKey) =
        pubKey.AsSshPublicKey

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
    static member OfRsaPublicKeyPem (pem:string) =
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
        RsaPublicKey(exported.Exponent, forcePosMod)

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
    static member ToRsaPublicKey (pubKey:RsaPublicKey) =
        RSA.Create(RSAParameters(Exponent=pubKey.Exponent, Modulus=pubKey.Modulus))
