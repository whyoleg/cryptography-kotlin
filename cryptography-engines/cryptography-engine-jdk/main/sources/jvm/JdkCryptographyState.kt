package dev.whyoleg.cryptography.jdk

import java.security.*

//candidate for context receivers
//TODO: cache per state or provider, and not thread local
internal class JdkCryptographyState(
    val provider: JdkProvider,
    val secureRandom: SecureRandom,
)
