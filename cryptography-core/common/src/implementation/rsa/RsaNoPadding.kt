package dev.whyoleg.cryptography.implementation.rsa

import dev.whyoleg.cryptography.algorithm.*
import dev.whyoleg.cryptography.function.*

public interface RsaNoPadding : Rsa<RsaNoPadding.PublicKey, RsaNoPadding.PrivateKey, RsaNoPadding.KeyPair> {
    public interface PublicKey : Rsa.PublicKey<Unit, EncryptFunction>
    public interface PrivateKey : Rsa.PrivateKey<Unit, DecryptFunction>
    public interface KeyPair : Rsa.KeyPair<PublicKey, PrivateKey>
}
