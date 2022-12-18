package dev.whyoleg.cryptography.jdk

import java.security.*

//candidate for context receivers
internal class JdkCryptographyState(
    val provider: JdkProvider,
    val secureRandom: SecureRandom,
)
