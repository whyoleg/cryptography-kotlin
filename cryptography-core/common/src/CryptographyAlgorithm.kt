package dev.whyoleg.cryptography

import dev.whyoleg.cryptography.key.*
import dev.whyoleg.vio.*

public interface CryptographyFunction : Closeable

public interface CryptographyAlgorithm<Primitive : CryptographyPrimitive> {

    public interface ForCreate<
            Primitive : CryptographyPrimitive,
            Parameters : CryptographyParameters<Primitive>,
            Builder : CryptographyParametersBuilder<Primitive, Parameters>
            > : CryptographyAlgorithm<Primitive> {
        public fun builderForCreate(): Builder
    }

    public interface ForGenerate<
            Primitive : CryptographyPrimitive,
            Parameters : CryptographyParameters<Primitive>,
            Builder : CryptographyParametersBuilder<Primitive, Parameters>
            > : CryptographyAlgorithm<Primitive> {
        public fun builderForGenerate(): Builder
    }

    public interface ForKeyDecode<
            Format : KeyFormat, //TODO: move type parameter
            Primitive : KeyPrimitive,
            Parameters : CryptographyParameters<Primitive>,
            Builder : CryptographyParametersBuilder<Primitive, Parameters>
            > : CryptographyAlgorithm<Primitive> {
        public fun builderForKeyDecode(): Builder
    }

}

public inline fun <
        Primitive : CryptographyPrimitive,
        Parameters : CryptographyParameters<Primitive>,
        Builder : CryptographyParametersBuilder<Primitive, Parameters>
        > CryptographyAlgorithm.ForCreate<*, Parameters, Builder>.forCreate(
    block: Builder.() -> Unit = {}
): Parameters {
    return builderForCreate().apply(block).build()
}
