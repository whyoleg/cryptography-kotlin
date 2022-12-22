package dev.whyoleg.cryptography.jdk.internal

import dev.whyoleg.cryptography.jdk.*
import dev.whyoleg.cryptography.provider.*
import java.security.*

//candidate for context receivers
//TODO: cache per state or provider, and not thread local
internal class JdkCryptographyState(
    val provider: JdkProvider,
    val secureRandom: SecureRandom,
    val adaptor: SuspendAdaptor?,
) {
    suspend inline fun <T> execute(crossinline block: () -> T): T = adaptor?.execute { block() } ?: block()
}
