package dev.whyoleg.vio

public interface BinaryCoder : BinaryEncoder, BinaryDecoder

public interface BinaryEncoder {
    //TODO: outputSize function?
    public fun encode(input: BufferView): BufferView
    public fun encode(input: BufferView, output: BufferView): BufferView
}

public interface BinaryDecoder {
    public fun decode(input: BufferView): BufferView
    public fun decode(input: BufferView, output: BufferView): BufferView
}

//TODO: same name as in kx.serialization
public interface BinaryFormat : BinaryFormatter, BinaryParser

public interface BinaryFormatter {
    public fun format(input: BufferView): String
    public fun format(input: BufferView, output: StringBuilder)
}

public interface BinaryParser {
    public fun parse(input: String): BufferView
    public fun parse(input: String, output: BufferView): BufferView
}

public expect object Base64 : BinaryCoder, BinaryFormat

public expect object Hex : BinaryCoder, BinaryFormat
