/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.operations

import dev.whyoleg.cryptography.binary.*
import dev.whyoleg.cryptography.providers.jdk.*

internal fun Pooled<JKeyAgreement>.doAgreement(
    state: JdkCryptographyState,
    privateKey: JPrivateKey,
    publicKey: JPublicKey,
): BinaryData = use {
    it.init(privateKey, state.secureRandom)
    it.doPhase(publicKey, true)
    BinaryData.fromByteArray(it.generateSecret())
}
