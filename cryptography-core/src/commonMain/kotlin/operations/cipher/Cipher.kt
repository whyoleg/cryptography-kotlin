package dev.whyoleg.cryptography.operations.cipher

import dev.whyoleg.cryptography.provider.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface Cipher : Encryptor, Decryptor