/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.api

import android.os.*

internal actual val currentTestPlatform: TestPlatform = TestPlatform.Android(
    apiLevel = Build.VERSION.SDK_INT
)
