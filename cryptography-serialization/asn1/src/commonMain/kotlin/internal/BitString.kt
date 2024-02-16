/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.asn1.internal

import dev.whyoleg.cryptography.serialization.asn1.*
import kotlinx.serialization.*
import kotlinx.serialization.builtins.*
import kotlinx.serialization.descriptors.*

@ExperimentalSerializationApi
internal fun SerialDescriptor.isElementBitString(index: Int): Boolean {
    return getElementDescriptor(index) == ByteArraySerializer().descriptor &&
            getElementAnnotations(index).any { it is ByteArrayAsBitString }
}
