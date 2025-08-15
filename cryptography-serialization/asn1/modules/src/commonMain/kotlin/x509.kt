/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.asn1.modules

import dev.whyoleg.cryptography.bigint.*
import dev.whyoleg.cryptography.bits.*
import dev.whyoleg.cryptography.serialization.asn1.*
import kotlinx.serialization.*
import kotlin.jvm.*

//Certificate  ::=  SEQUENCE  {
//        tbsCertificate       TBSCertificate,
//        signatureAlgorithm   AlgorithmIdentifier,
//        signatureValue       BIT STRING  }
@Serializable
public class Certificate(
    public val tbsCertificate: TbsCertificate,
    public val signatureAlgorithm: AlgorithmIdentifier,
    public val signatureValue: BitString,
)

//   TBSCertificate  ::=  SEQUENCE  {
//        version         [0]  EXPLICIT Version DEFAULT v1,
//        serialNumber         CertificateSerialNumber,
//        signature            AlgorithmIdentifier,
//        issuer               Name,
//        validity             Validity,
//        subject              Name,
//        subjectPublicKeyInfo SubjectPublicKeyInfo,
//        issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
//                             -- If present, version MUST be v2 or v3
//        subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
//                             -- If present, version MUST be v2 or v3
//        extensions      [3]  EXPLICIT Extensions OPTIONAL
//                             -- If present, version MUST be v3
//        }
//
@Serializable
public class TbsCertificate(
    public val version: Int = 0, // TODO EXPLICIT?
    public val serialNumber: CertificateSerialNumber,
    public val signature: AlgorithmIdentifier,
    public val issuer: Name,
    public val validity: Validity,
    public val subject: Name,
    public val subjectPublicKeyInfo: SubjectPublicKeyInfo,
    public val issuerUniqueID: UniqueIdentifier? = null,
    public val subjectUniqueID: UniqueIdentifier? = null,
    public val extensions: Extensions? = null,
)

public typealias CertificateSerialNumber = BigInt

@Serializable
public class Validity(
    public val notBefore: Time,
    public val notAfter: Time,
)

// TODO!!!
@Serializable
public class Time(
    public val utcTime: String? = null,
    public val generalTime: String? = null,
)

public typealias UniqueIdentifier = BitString

public typealias Extensions = List<Extension>

@Serializable
public class Extension(
    public val extnID: ObjectIdentifier,
    public val critical: Boolean = false,
    public val extnValue: ByteArray,
)

@Serializable
@JvmInline
public value class Name(
    public val s: String, // TODO!!!
)

//Name ::= CHOICE { -- only one possibility for now --
//    rdnSequence  RDNSequence }
//
//RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
//
//RelativeDistinguishedName ::=
//SET SIZE (1..MAX) OF AttributeTypeAndValue
//
//AttributeTypeAndValue ::= SEQUENCE {
//    type     AttributeType,
//    value    AttributeValue }
//
//AttributeType ::= OBJECT IDENTIFIER
//
//AttributeValue ::= ANY -- DEFINED BY AttributeType
//
//DirectoryString ::= CHOICE {
//    teletexString           TeletexString (SIZE (1..MAX)),
//    printableString         PrintableString (SIZE (1..MAX)),
//    universalString         UniversalString (SIZE (1..MAX)),
//    utf8String              UTF8String (SIZE (1..MAX)),
//    bmpString               BMPString (SIZE (1..MAX)) }
