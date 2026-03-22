# Module cryptography-core

Provides a multiplatform API to build, get and use cryptography primitives.

Core concepts:

* [CryptographyProvider][dev.whyoleg.cryptography.CryptographyProvider] provides a way to get a
  specific [CryptographyAlgorithm][dev.whyoleg.cryptography.CryptographyAlgorithm]
* [CryptographyProvider.Default][dev.whyoleg.cryptography.CryptographyProvider.Default] is the auto-configured default provider
* [CryptographySystem][dev.whyoleg.cryptography.CryptographySystem] manages global state: default provider, provider registry, and default
  random

# Package dev.whyoleg.cryptography

Core primitives for creating and accessing [CryptographyAlgorithm][dev.whyoleg.cryptography.CryptographyAlgorithm]
and [CryptographyProvider][dev.whyoleg.cryptography.CryptographyProvider].

# Package dev.whyoleg.cryptography.algorithms

Algorithm definitions covering
digests (like [SHA256][dev.whyoleg.cryptography.algorithms.SHA256] or [SHA512][dev.whyoleg.cryptography.algorithms.SHA512]),
symmetric ciphers (like [AES.GCM][dev.whyoleg.cryptography.algorithms.AES.GCM]
or [ChaCha20Poly1305][dev.whyoleg.cryptography.algorithms.ChaCha20Poly1305]),
digital signatures (like [ECDSA][dev.whyoleg.cryptography.algorithms.ECDSA] or [EdDSA][dev.whyoleg.cryptography.algorithms.EdDSA]),
MAC ([HMAC][dev.whyoleg.cryptography.algorithms.HMAC]),
key derivation ([PBKDF2][dev.whyoleg.cryptography.algorithms.PBKDF2], [HKDF][dev.whyoleg.cryptography.algorithms.HKDF]),
and key agreement ([ECDH][dev.whyoleg.cryptography.algorithms.ECDH], [DH][dev.whyoleg.cryptography.algorithms.DH]).

# Package dev.whyoleg.cryptography.operations

APIs for performing different cryptographic operations:
[encryption/decryption][dev.whyoleg.cryptography.operations.Cipher],
[hashing][dev.whyoleg.cryptography.operations.Hasher],
[signatures][dev.whyoleg.cryptography.operations.SignatureGenerator],
[key derivation][dev.whyoleg.cryptography.operations.SecretDerivation],
[key agreement][dev.whyoleg.cryptography.operations.SharedSecretGenerator],
and [key management][dev.whyoleg.cryptography.operations.KeyGenerator].

# Package dev.whyoleg.cryptography.materials

Encoding and decoding of cryptographic materials (keys, parameters).
