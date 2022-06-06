package dev.whyoleg.cryptography.cipher

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.key.*

//does type is needed?
public interface CipherPrimitive<K : CipherKey> : CryptographyPrimitive {
    //import, generate, etc depending on
}

public interface CipherKey : Key

//TODO: symmetric cipher naming?
public interface CipherSecretKey : CipherKey, SecretKey {
    public val encrypt: CipherOperation
    public val decrypt: CipherOperation
}

public interface CipherPublicKey : CipherKey, PublicKey {
    public val encrypt: CipherOperation
}

public interface CipherPrivateKey : CipherKey, PrivateKey {
    public val decrypt: CipherOperation
}

public interface CipherKeyPair : KeyPair {
    public val publicKey: CipherPublicKey
    public val privateKey: CipherPrivateKey
}
