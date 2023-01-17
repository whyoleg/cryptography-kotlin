package dev.whyoleg.cryptography.apple

import dev.whyoleg.cryptography.provider.*

internal class AppleState(
    val adaptor: SuspendAdaptor?,
) {
    suspend inline fun <T> execute(crossinline block: () -> T): T = adaptor?.execute { block() } ?: block()
}
