package dev.whyoleg.cryptography.algorithms.new

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.cipher.*
import dev.whyoleg.cryptography.key.*

public interface RsaPublicKey : CryptographyKey.Public
public interface RsaPrivateKey : CryptographyKey.Private
public interface RsaKeyPair : CryptographyKey.Pair {
    override val publicKey: RsaPublicKey
    override val privateKey: RsaPrivateKey
}

public class RsaOaepBuilder {

}

public class RsaOaepParameters(

)

public inline fun RsaOaepParameters(
    block: RsaOaepBuilder.() -> Unit,
): RsaOaepParameters {

}

public inline fun CryptographyProvider.RsaOaepEncryptor(
    publicKey: RsaPublicKey,
    block: RsaOaepBuilder.() -> Unit = {},
): Encryptor.Sync<CipherBox> {

}

public inline fun CryptographyProvider.RsaOaepEncryptor(
    publicKey: RsaPublicKey,
    parameters: RsaOaepParameters,
): Encryptor.Sync<CipherBox> {

}
