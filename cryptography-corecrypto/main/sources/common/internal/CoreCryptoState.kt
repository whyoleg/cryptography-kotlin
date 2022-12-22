package dev.whyoleg.cryptography.corecrypto.internal

import dev.whyoleg.cryptography.provider.*

internal class CoreCryptoState(
    val adaptor: SuspendAdaptor?,
) {
    suspend inline fun <T> execute(crossinline block: () -> T): T = adaptor?.execute { block() } ?: block()
}
