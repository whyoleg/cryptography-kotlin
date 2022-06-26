package dev.whyoleg.cryptography.alg

import dev.whyoleg.cryptography.*

public class AesGcmBox(
    public val initializationVector: InitializationVector,
    ciphertext: Ciphertext,
    public val authTag: AuthTag
) : CipherBox(ciphertext)

public class AesCtrBox(
    public val initializationVector: InitializationVector,
    ciphertext: Ciphertext
) : CipherBox(ciphertext)


//start with:
//encryption/decryption: AES(CTR, CBC, GCM), RSA(OAEP)
//hash: SHA(1, 2, 3), SHAKE(128, 256)
//mac: HMAC(ANY HASH) +, CMAC(AES-CBC), GMAC(AES-GCM)
//sing/verify: RSA(SSA, PSS), ECDSA

public interface RsaOaepPublicKey
    : EncryptorProvider

public interface RsaOaepPrivateKey
    : DecryptorProvider

public interface AesGcmKey:
    AeadCipherProvider,
    BoxedAeadCipherProvider<AesGcmBox>,
    StreamAeadCipherProvider,
    KeyEncoder<KeyFormat.RAW>

public interface AeadCipherProvider: AeadEncryptorProvider, AeadDecryptorProvider {
    public fun cipher(kind, parameters)
    public fun cipher(kind, block)
}

public interface StreamAeadEncryptorProvider {
    public fun streamEncryptor()
}

//symmetric, public, private, key pair - different formats, etc
public interface KeyEncoder {
    public fun
}