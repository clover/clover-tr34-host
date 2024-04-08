# TR-34 host and authority sample implementation

TR-34 is an interoperable cryptographic protocol for remotely injecting symmetric keys in a secure
fashion. Financial institutions may use TR-34 to transmit symmetric keys between secure 
cryptographic devices using asymmetric cryptography techniques.

This pure java implementation is based on the ASC X9 TR 34–2019 edition developed through the
Accredited Standards Committee X9, Inc available for purchase online at https://webstore.ansi.org/.

A common use of TR-34 is to remotely inject a terminal master key (TMK) from a key distribution
host (KDH) to a payment terminal or ATM. After the TMK is successfully injected a protocol such
as ASC X9.143 (formerly TR-31) can be used to remotely inject specific keys such as a PIN
encryption key.

This project contains the key distribution host and device authority implementation of the TR-34
protocol. This is best used to verify the implementation of a TR-34 client running on key receiving
device, which is not included in this project though there are some example methods to do basic
token verification and decryption that can be used as a guide.

It should be possible to modify this code such that the cryptographic key storage and raw
cryptographic operations are performed within an HSM, but there is currently no interface in this
project to do so as-is. The implementation of the most critical function--the construction of key
exchange token--must be performed entirely within an HSM since it requires access to sensitive
symmetric key material that must also be contained within an HSM. As it is this project is
currently not ready to be deployed in a production environment.

This implementation only supports the creation of the two pass key token, the one pass key token
is not supported.

### Getting Started

The primary class for interacting with this library is the Tr34TokenFactory. The Tr34TokenClient
also contains essential methods for verifying/decrypting tokens. The CloverSampleTr34KeyStoreData
class holds sample keys and certificates which can be used to verify TR-34 functionality and
produce sample TR-34 tokens.

### Caveats

A few of the ASC provided samples are not fully compatible with this project for a variety of
reasons, it may be possible to adapt this project to fully accept them but there is no plan to do
so. See notes in the Tr34AscX9Test class for precise explanations on which samples are not
functional and why.

One flaw with TR-34 in the author's opinion is the use of a single root CA for both the KDH and
KRD. Using a single root leads to the unfortunate consequence that in a naive implementation a
rogue KRD could act as a KDH and a rogue KDH could act as a KRD. A rogue KRD is far more likely
and dangerous scenario. To comply with TR-34 but prevent this attack it is suggested that
implementations require certificates in the KRD chain to contain a string such as "KRD" in the CN,
and require certificates in the KDH chain to contain a string "KDH" in the CN.

### License

See the LICENSE included in this project for copyright details.
