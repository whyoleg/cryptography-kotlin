package dev.whyoleg.cryptography.signature

import dev.whyoleg.cryptography.new.*
import dev.whyoleg.vio.*

public interface Verifier : CryptographyPrimitive {
    public interface Sync : Verifier {
        public val signatureSize: BinarySize

        public fun verify(input: BufferView): Boolean
    }

    public interface Async : Verifier {
        public val signatureSize: BinarySize

        public suspend fun verify(input: BufferView): Boolean
    }

    public interface Stream : Verifier {
        public fun createVerifyFunction(): VerifyFunction
    }
}
