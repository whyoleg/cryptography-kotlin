/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package ckbuild

import org.jetbrains.kotlin.gradle.plugin.*

fun LanguageSettingsBuilder.optInForTests() {
    optIn("kotlin.experimental.ExperimentalNativeApi")
    optIn("kotlin.io.encoding.ExperimentalEncodingApi")
    optIn("kotlinx.coroutines.ExperimentalCoroutinesApi")
    optInForProvider()
}

fun LanguageSettingsBuilder.optInForProvider() {
    optIn("dev.whyoleg.cryptography.CryptographyProviderApi")
    optIn("dev.whyoleg.cryptography.InsecureAlgorithm")
}
