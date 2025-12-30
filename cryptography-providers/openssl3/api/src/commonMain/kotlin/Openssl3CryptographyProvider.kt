/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3

import dev.whyoleg.cryptography.*

private val defaultProvider = lazy { Openssl3CryptographyProvider }

public val CryptographyProvider.Companion.Openssl3: CryptographyProvider by defaultProvider

internal object Openssl3CryptographyProvider : BaseOpenssl3CryptographyProvider()

@Suppress("DEPRECATION")
@OptIn(ExperimentalStdlibApi::class)
@EagerInitialization
private val initHook = CryptographySystem.registerProvider(defaultProvider, 100)
