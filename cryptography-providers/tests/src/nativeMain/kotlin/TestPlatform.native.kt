/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests

import kotlin.experimental.*

@OptIn(ExperimentalNativeApi::class)
internal actual val currentTestPlatform: TestPlatform = TestPlatform.Native(
    os = Platform.osFamily.toString(),
    arch = Platform.cpuArchitecture.toString(),
    debug = Platform.isDebugBinary
)
