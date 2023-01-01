package dev.whyoleg.cryptography.apple

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.provider.*
import kotlinx.cinterop.*
import platform.CoreCrypto.*

internal class AppleState(
    val adaptor: SuspendAdaptor?,
) {
    suspend inline fun <T> execute(crossinline block: () -> T): T = adaptor?.execute { block() } ?: block()
}

internal fun randomBytes(size: Int): ByteArray = ByteArray(size).also(::randomBytes)

internal fun randomBytes(output: ByteArray): ByteArray {
    if (
        CCRandomGenerateBytes(output.refTo(0), output.size.convert()) != kCCSuccess
    ) throw CryptographyException("CCRandomGenerateBytes failed")
    return output
}
