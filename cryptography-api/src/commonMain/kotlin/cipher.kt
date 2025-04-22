/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.api

import kotlinx.io.*
import kotlinx.io.bytestring.*

public interface CipherBox {
    public val combined: ByteString
}

//

public interface EncryptPrimitive<P> : CryptographyPrimitive {
    public fun encrypt(plaintext: ByteString, parameters: P): ByteString
}

public interface BoxEncryptPrimitive<P, SB : CipherBox> : CryptographyPrimitive {
    public fun encryptToBox(plaintext: ByteString, parameters: P): SB
}

public interface StreamingEncryptPrimitive<P> : CryptographyPrimitive {
    public fun encryptingSource(plaintext: RawSource, parameters: P): RawSource
}

public interface DecryptPrimitive<P> : CryptographyPrimitive {
    public fun decrypt(ciphertext: ByteString, parameters: P): ByteString
}

public interface BoxDecryptPrimitive<P, SB : CipherBox> : CryptographyPrimitive {
    public fun decryptFromBox(cipherbox: SB, parameters: P): ByteString
}

public interface StreamingDecryptPrimitive<P> : CryptographyPrimitive {
    public fun decryptingSource(ciphertext: RawSource, parameters: P): RawSource
}

//

public interface AsyncEncryptPrimitive<P> : CryptographyPrimitive {
    public suspend fun encrypt(plaintext: ByteString, parameters: P): ByteString
}

public interface AsyncDecryptPrimitive<P> : CryptographyPrimitive {
    public suspend fun decrypt(ciphertext: ByteString, parameters: P): ByteString
}
