package dev.whyoleg.cryptography.jdk

import dev.whyoleg.cryptography.jdk.internal.*
import dev.whyoleg.cryptography.provider.*
import java.security.*

public val CryptographyProvider.Companion.JDK: CryptographyProvider by lazy(CryptographyProvider.Companion::JDK)

@Suppress("FunctionName")
public fun CryptographyProvider.Companion.JDK(
    secureRandom: SecureRandom = SecureRandom(),
    provider: JdkProvider = JdkProvider.Default,
    adaptor: SuspendAdaptor? = null,
): CryptographyProvider = JdkCryptographyProvider(JdkCryptographyState(provider, secureRandom, adaptor))
