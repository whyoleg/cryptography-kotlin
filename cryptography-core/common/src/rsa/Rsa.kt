package dev.whyoleg.cryptography.rsa

import dev.whyoleg.cryptography.cipher.*
import dev.whyoleg.cryptography.key.*

public sealed class RsaKeyPairGenerationParameters<K : RsaKeyPair>(
    public val keySize: KeySize,
    public val publicExponent: String //TODO BigInteger
) : KeyGenerationParameters<K>

public interface RsaKeyPair : KeyPair {
    public val publicKey: RsaPublicKey
    public val privateKey: RsaPrivateKey
}

public interface RsaPublicKey : PublicKey
public interface RsaPrivateKey : PublicKey

public interface RsaEncryptor : Encryptor<Unit>
public interface RsaDecryptor : Encryptor<Unit>
