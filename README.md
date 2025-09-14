SshCA
=====

Use SSH public key and and CA certificates to sign SSH public keys. It can be used to read and write SSH public keys, convert between dotnet RSA public keys and the OpenSSH format, and to sign OpenSSH public keys in the format used by OpenSSH.

See the [SshCA.Tests](SshCA.Tests) project for examples.

### Features
* Read OpenSSH public keys and convert them to RSA public keys
* Read RSA public keys from a PEM file for use with signing.
* Write RSA public keys as OpenSSH public keys
* Sign OpenSSH public keys with an RSA implementation such as `System.Security.Cryptography.RSA` or the one returned by `Azure.Security.KeyVault.Keys.Cryptography.CryptographyClient.CreateRSA`.
