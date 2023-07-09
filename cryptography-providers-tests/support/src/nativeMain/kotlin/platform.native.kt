/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.support

actual val currentPlatform: String by lazy {
    "Native [os=${Platform.osFamily}, arch=${Platform.cpuArchitecture}, debug=${Platform.isDebugBinary}]"
}
