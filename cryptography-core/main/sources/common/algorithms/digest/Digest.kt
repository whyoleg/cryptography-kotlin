@file:OptIn(CryptographyProviderApi::class)

package dev.whyoleg.cryptography.algorithms.digest

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.operations.hash.*
import dev.whyoleg.cryptography.provider.*

//simple hash algorithms, that can be used in HMAC/ECDSA contexts
@SubclassOptInRequired(CryptographyProviderApi::class)
public interface Digest : CryptographyAlgorithm {
    public fun hasher(): Hasher
}

@InsecureAlgorithm
public object MD5 : CryptographyAlgorithmId<Digest>()

@InsecureAlgorithm
public object SHA1 : CryptographyAlgorithmId<Digest>()
public object SHA256 : CryptographyAlgorithmId<Digest>()
public object SHA384 : CryptographyAlgorithmId<Digest>()
public object SHA512 : CryptographyAlgorithmId<Digest>()

public object SHA3 {
    public object B224 : CryptographyAlgorithmId<Digest>()
    public object B512 : CryptographyAlgorithmId<Digest>()
}
