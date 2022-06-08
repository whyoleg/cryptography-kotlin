package dev.whyoleg.bignumber

public expect class BigInt : Number, Comparable<BigInt> {
    //TODO: decide on API, for now I need only strings and bytearrays
    public constructor(value: Int)
    public constructor(value: Long)
    public constructor(value: String, radix: Int = 10)
    public constructor(value: ByteArray)
    //add all operators like plus, minus, etc


    //TODO: move from class?
    public override fun toString(): String
    public fun toString(radix: Int): String

    public fun encodeToByteArray(): ByteArray
}

//public expect fun BigInt(value: String): BigInt
//public expect fun BigInt(value: ByteArray): BigInt