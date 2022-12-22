package dev.whyoleg.cryptography.operations

//TODO: revisit naming, inner classes, etc.
public abstract class CryptographyOperationParameters {
    public object Empty : CryptographyOperationParameters()
    public abstract class Copyable<P : Copyable<P, B>, B> : CryptographyOperationParameters() {
        protected abstract fun createBuilder(): B
        protected abstract fun buildFrom(builder: B): P

        public inline fun copy(block: B.() -> Unit): P = createBuilderInternal().apply(block).let(::buildFromInternal)

        @PublishedApi
        internal fun createBuilderInternal(): B = createBuilder()

        @PublishedApi
        internal fun buildFromInternal(builder: B): P = buildFrom(builder)
    }

}
