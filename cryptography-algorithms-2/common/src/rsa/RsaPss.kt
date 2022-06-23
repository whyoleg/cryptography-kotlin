package dev.whyoleg.cryptography.rsa

import dev.whyoleg.cryptography.hash.*
import dev.whyoleg.cryptography.key.*
import dev.whyoleg.cryptography.signature.*
import dev.whyoleg.vio.*

public class RsaPssKeyPairGenerationParameters(
    keySize: KeySize,
    publicExponent: String
) : RsaKeyPairGenerationParameters<RsaPssKeyPair>(keySize, publicExponent)

public interface RsaPssKeyPair : RsaKeyPair {
    override val publicKey: RsaPssPublicKey
    override val privateKey: RsaPssPrivateKey
}

public interface RsaPssPublicKey : RsaPublicKey {
    public fun verifier(
        hash: HashParameters,
        saltSize: BinarySize
        //TODO: add mgf
    ): Verifier
}

public interface RsaPssPrivateKey : RsaPrivateKey {
    public fun signer(
        hash: HashParameters,
        saltSize: BinarySize
        //TODO: add mgf
    ): Signer
}
