package dev.whyoleg.cryptography.rsa

import dev.whyoleg.cryptography.hash.*
import dev.whyoleg.cryptography.key.*

public class RsaOaepKeyPairGenerationParameters(
    keySize: KeySize,
    publicExponent: String
) : RsaKeyPairGenerationParameters<RsaOaepKeyPair>(keySize, publicExponent)

public interface RsaOaepKeyPair : RsaKeyPair {
    override val publicKey: RsaOaepPublicKey
    override val privateKey: RsaOaepPrivateKey
}

public interface RsaOaepPublicKey : RsaPublicKey {
    public fun encryptor(
        hash: HashParameters,
        //TODO: add mgf
    ): RsaEncryptor
}

public interface RsaOaepPrivateKey : RsaPrivateKey {
    public fun decryptor(
        hash: HashParameters,
        //TODO: add mgf
    ): RsaDecryptor
}
