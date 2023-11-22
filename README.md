# TR-34 host and authority sample implementation

TR-34 is an interoperable cryptographic protocol for remotely injecting symmetric keys in a secure
fashion. Financial institutions may use TR-34 to transmit symmetric keys between secure 
cryptographic devices using asymmetric cryptography techniques.

This implementation is based on the ASC X9 TR 34–2019 edition developed through the
Accredited Standards Committee X9, Inc available for purchase online at https://webstore.ansi.org/.

A common use of TR-34 is to remotely inject a terminal master key (TMK) from a key distribution
host (KDH) to a payment terminal or ATM. After the TMK is successfully injected a protocol such
as TR-31 can be used to remotely inject specific keys such as a PIN encryption key.

This project contains the key distribution host and device authority implementation of the TR-34
protocol. This is best used to verify the implementation of a TR-34 client running on key receiving
device, which is not included in this project though there are some methods to do basic token 
verification.

Theoretically it may be possible to modify this code such that the cryptographic key storage and
raw cryptographic operations are performed within an HSM, but there is currently no interface in
this project to do so and as-is this project is not intended for use in a production environment
since an HSM is almost certainly going to be required for any production key distribution host.

The primary class for interacting with this library is the Tr34TokenFactory. The 
CloverDevTr34KeyStoreData holds keys and certificates which can be used to verify TR-34
functionality.

## Build and Test

    mvn package

See the LICENSE included in this project for copyright details.
