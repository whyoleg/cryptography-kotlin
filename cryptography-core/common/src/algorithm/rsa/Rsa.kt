package dev.whyoleg.cryptography.algorithm.rsa

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithm.aes.*
import dev.whyoleg.vio.*

public interface Rsa : CryptographyAlgorithm {
    public val keyPair: RsaKeyPairFactory
    public val publicKey: RsaPublicKeyFactory
    public val privateKey: RsaPrivateKeyFactory
}

public interface RsaKeyPairFactory {
    public fun generateKeyPair(keySize: BinarySize): RsaKeyPair
    public fun importKeyPair(keyPair: BufferView): AesKey //TODO: other imports
}

public interface RsaPublicKeyFactory {

}

public interface RsaPrivateKeyFactory {

}

public interface RsaPublicKey {

}

public interface RsaPrivateKey {

}

public interface RsaKeyPair {

}
