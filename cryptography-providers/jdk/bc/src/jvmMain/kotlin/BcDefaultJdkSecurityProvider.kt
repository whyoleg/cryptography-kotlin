/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.bc

import dev.whyoleg.cryptography.providers.jdk.*
import org.bouncycastle.jce.provider.*
import java.security.*

private val defaultSecurityProvider = lazy { BouncyCastleProvider() }

internal class BcDefaultJdkSecurityProvider : DefaultJdkSecurityProvider {
    override val provider: Lazy<Provider> get() = defaultSecurityProvider
}
