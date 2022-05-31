package dev.whyoleg.cryptography.implementation.rsa

import dev.whyoleg.cryptography.algorithm.*
import dev.whyoleg.cryptography.function.*

public interface RsaOaep : Rsa<RsaOaep.PublicKey, RsaOaep.PrivateKey, RsaOaep.KeyPair> {
    public interface PublicKey : Rsa.PublicKey<Unit, EncryptFunction>
    public interface PrivateKey : Rsa.PrivateKey<Unit, DecryptFunction>
    public interface KeyPair : Rsa.KeyPair<PublicKey, PrivateKey>
}
