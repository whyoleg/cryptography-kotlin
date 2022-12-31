package dev.whyoleg.cryptography.apple

import dev.whyoleg.cryptography.apple.internal.*
import dev.whyoleg.cryptography.provider.*

public val CryptographyProvider.Companion.CoreCrypto: CryptographyProvider by lazy(CryptographyProvider.Companion::CoreCrypto)

@Suppress("FunctionName")
public fun CryptographyProvider.Companion.CoreCrypto(
    adaptor: SuspendAdaptor? = null,
): CryptographyProvider = CoreCryptoCryptographyProvider(CoreCryptoState(adaptor))
