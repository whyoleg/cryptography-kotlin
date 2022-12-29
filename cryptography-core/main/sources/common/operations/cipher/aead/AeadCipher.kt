package dev.whyoleg.cryptography.operations.cipher.aead

import dev.whyoleg.cryptography.operations.cipher.*

public interface AeadCipher : Cipher, AeadEncryptor, AeadDecryptor

