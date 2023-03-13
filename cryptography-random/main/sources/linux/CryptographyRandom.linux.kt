package dev.whyoleg.cryptography.random

internal actual fun defaultCryptographyRandom(): CryptographyRandom = createGetRandom() ?: createURandom()
