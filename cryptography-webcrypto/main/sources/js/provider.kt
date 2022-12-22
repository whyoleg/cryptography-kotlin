package dev.whyoleg.cryptography.webcrypto

import dev.whyoleg.cryptography.provider.*
import dev.whyoleg.cryptography.webcrypto.internal.*

public val CryptographyProvider.Companion.WebCrypto: CryptographyProvider get() = WebCryptoCryptographyEngine
