/*
 * Copyright (c) 2024-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.asn1

import kotlinx.serialization.*

@Target(AnnotationTarget.PROPERTY)
@OptIn(ExperimentalSerializationApi::class)
@SerialInfo
public annotation class ContextSpecificTag(
    public val classIndex: Byte,
    public val type: TagType,
) {
    // EXPLICIT is default
    public enum class TagType { IMPLICIT, EXPLICIT }
}

// replacement for `ContextSpecificTag`
// target: property and type?
@Target(AnnotationTarget.PROPERTY)
@OptIn(ExperimentalSerializationApi::class)
@SerialInfo
public annotation class Asn1Tag(
    public val value: Byte,
    public val tagType: TagType, // TODO may be just flag? `isImplicit`?
    // public val tagClass: TagClass = TagClass.ContextSpecific,
) {
    // make it top-level?
    public enum class TagType { IMPLICIT, EXPLICIT }
    // public enum class TagClass { ContextSpecific, Universal, Application, Private }
}

@Target(AnnotationTarget.PROPERTY)
@OptIn(ExperimentalSerializationApi::class)
@SerialInfo
public annotation class Asn1TimeFormat(
    public val decoding: Array<Kind>,
    public val encoding: Kind,
) {
    public enum class Kind { UTCTime, GeneralizedTime }
}

// Time ::= CHOICE { utcTime UTCTime, generalTime GeneralizedTime }

// @AsnChoice - do we need this?
//private sealed class Time {
//    abstract val value: Instant
//    // @ContextSpecificTag(0, IMPLICIT)
//    value class utcTime(@Asn1UTCTime val value: Instant) : Time()
//    // @ContextSpecificTag(1, IMPLICIT)
//    value class generalTime(@Asn1GeneralizedTime val value: Instant) : Time()
//}

// CHOICE:

// by type
// MessageType ::= CHOICE {
//                  text         OCTET STRING,
//                  codedNumeric INTEGER}

// by tag
// Division ::= CHOICE {
//                  manufacturing  [0] IMPLICIT SEQUENCE {
//                                         plantID      INTEGER,
//                                         majorProduct IA5String},
//                  r-and-d        [1] IMPLICIT   SEQUENCE {
//                                         labID          INTEGER,
//                                         currentProject IA5String},
//                 unassigned      [2] IMPLICIT  NULL
//                 }

// asn1 elements:
// - Asn1Boolean
// - Asn1Integer - bigint
// - Asn1BitString
// - Asn1OctetString
// - Asn1Null
// - Asn1ObjectIdentifier
// - Asn1Enumerated - enum?
// - Asn1Sequence(of) - list of elements
// - Asn1Set(of) - set(?) of elements
// - Asn1String + type
// - Asn1Time + type
// - Asn1Choice - ???

// UTCTime & GeneralizedTime - Instant
// DURATION - Duration

// DATE-TIME - LocalDateTime (kotlinx)
// TIME-OF-DAY - LocalTime (kotlinx)
// DATE - LocalDate (kotlinx)

//private val s = Instant.parse("2023-01-01T00:00:00Z")
