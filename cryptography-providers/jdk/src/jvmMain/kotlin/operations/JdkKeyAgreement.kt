/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.operations

import dev.whyoleg.cryptography.providers.jdk.*
import kotlinx.io.bytestring.*
import kotlinx.io.bytestring.unsafe.*

@OptIn(UnsafeByteStringApi::class)
internal fun Pooled<JKeyAgreement>.doAgreement(
    state: JdkCryptographyState,
    privateKey: JPrivateKey,
    publicKey: JPublicKey,
): ByteString = use {
    it.init(privateKey, state.secureRandom)
    it.doPhase(publicKey, true)
    UnsafeByteStringOperations.wrapUnsafe(it.generateSecret())
}
