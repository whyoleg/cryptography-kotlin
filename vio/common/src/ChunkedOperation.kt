package dev.whyoleg.vio

//TODO: decide on context - should it be different from parameters or not
// for now it's only used for AEAD context, which is not encoded there, but just context
// is it needed somewhere else?

//TODO: name? Updatable, Multipart, etc
public interface ChunkedOperation : Closeable
public interface ChunkableOperation<
        Context, //context of operation
        OP, OI, OO, OR, //operation parameters
        CP, CO : ChunkedOperation, //chunked operation parameters
        > {
    //TODO: Proper name
    public fun chunked(context: Context, parameters: CP): CO
    public operator fun invoke(context: Context, parameters: OP, input: OI, output: OO): OR
}

public inline operator fun <R, C, FP, F : ChunkedOperation> ChunkableOperation<C, *, *, *, *, FP, F>.invoke(
    context: C,
    parameters: FP,
    block: F.() -> R
): R {
    return chunked(context, parameters).use(block)
}

public interface BufferOutputChunkableOperation<
        Context,
        OP, OI, /*OO = BufferView*/ OR,
        CP, CO : ChunkedOperation,
        > : ChunkableOperation<
        Context,
        OP, OI, BufferView, OR,
        CP, CO,
        > {
    //shortcut for implicit creation of output buffer
    public operator fun invoke(context: Context, parameters: OP, input: OI): OR
}

public interface BufferChunkableOperation<
        Context,
        OP,
        CP, CO : ChunkedOperation,
        > : BufferOutputChunkableOperation<
        Context,
        OP, BufferView, BufferView,
        CP, CO,
        >
