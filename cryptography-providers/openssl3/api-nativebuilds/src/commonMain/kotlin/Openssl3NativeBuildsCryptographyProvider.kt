/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.providers.openssl3.algorithms.*
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import kotlinx.cinterop.*

private val defaultProvider = lazy { Openssl3NativeBuildsCryptographyProvider }

public val CryptographyProvider.Companion.Openssl3NativeBuilds: CryptographyProvider by defaultProvider

internal object Openssl3NativeBuildsCryptographyProvider : BaseOpenssl3CryptographyProvider() {
    override val name: String = "OpenSSL3 (${OpenSSL_version(OPENSSL_VERSION_STRING)?.toKString() ?: "unknown"})"

    @Suppress("UNCHECKED_CAST")
    override fun <A : CryptographyAlgorithm> getOrNull(identifier: CryptographyAlgorithmId<A>): A? = when (identifier) {
        // Newer OpenSSL APIs can be added here (e.g. 3.6.0 adds ML-KEM)
        else      -> super.getOrNull(identifier)
    } as A?
}

@Suppress("DEPRECATION")
@OptIn(ExperimentalStdlibApi::class)
@EagerInitialization
private val initHook = CryptographySystem.registerProvider(defaultProvider, 100)
