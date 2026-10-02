/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests

import dev.whyoleg.cryptography.testhost.*
import kotlinx.serialization.*

@Serializable
data class TestContext(
    val platform: TestPlatform,
    val provider: TestProvider,
)
