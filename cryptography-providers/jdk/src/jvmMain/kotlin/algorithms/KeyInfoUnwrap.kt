package dev.whyoleg.cryptography.providers.jdk.algorithms

import dev.whyoleg.cryptography.serialization.asn1.*
import dev.whyoleg.cryptography.serialization.asn1.modules.*
import dev.whyoleg.cryptography.providers.base.materials.*

internal object KeyInfoUnwrap {
    fun unwrapPkcs8ForOids(der: ByteArray, oids: List<ObjectIdentifier>): ByteArray {
        var lastError: Throwable? = null
        for (oid in oids) {
            try {
                return unwrapPrivateKeyInfo(oid, der)
            } catch (t: Throwable) {
                lastError = t
            }
        }
        throw lastError ?: IllegalArgumentException("No OID matched for PKCS#8 unwrap")
    }
}
