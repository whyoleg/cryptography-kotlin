package dev.whyoleg.cryptography.primitives

import dev.whyoleg.cryptography.*

public interface CipherPrimitive<C> : EncryptPrimitive<C>, DecryptPrimitive<C>

public interface BoxCipherPrimitive<C, B : CipherBox> : CipherPrimitive<C>, BoxEncryptPrimitive<C, B>, BoxDecryptPrimitive<C, B>
