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
