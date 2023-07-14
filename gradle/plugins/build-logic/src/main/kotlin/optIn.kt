/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import org.jetbrains.kotlin.gradle.plugin.*

fun LanguageSettingsBuilder.optInForTests() {
    optIn("kotlin.experimental.ExperimentalNativeApi")
    optIn("kotlin.io.encoding.ExperimentalEncodingApi")
    optIn("kotlinx.coroutines.ExperimentalCoroutinesApi")
    optIn("dev.whyoleg.cryptography.provider.CryptographyProviderApi")
    optIn("dev.whyoleg.cryptography.algorithms.InsecureAlgorithm")
}
