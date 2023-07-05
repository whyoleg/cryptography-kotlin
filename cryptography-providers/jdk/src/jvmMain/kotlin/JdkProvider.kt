/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.jdk

import java.security.*

public sealed class JdkProvider private constructor(
    internal val name: String?,
) {
    public object Default : JdkProvider(null)
    public class Instance(public val provider: Provider) : JdkProvider(provider.name)
    public class Name(public val provider: String) : JdkProvider(provider)
}
