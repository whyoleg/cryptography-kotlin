package dev.whyoleg.cryptography.signature

import dev.whyoleg.cryptography.key.*

public interface MacSecretKey : SecretKey {
    public val sign: SignOperation
    public val verify: VerifyOperation
}

//TOTO public vs private - sign vs verify
public interface SignaturePublicKey : PublicKey {
    public val verify: VerifyOperation
}

public interface SignaturePrivateKey : PrivateKey {
    public val sign: SignOperation
}

public interface SignatureKeyPair : KeyPair {
    public val publicKey: SignaturePublicKey
    public val privateKey: SignaturePrivateKey
}
