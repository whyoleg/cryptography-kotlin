package dev.whyoleg.vio

//TODO: relative, link, absolute, take a look at okio files
public expect class PathView {
    public val isAbsolute: Boolean
    public val path: String
    public val absolutePath: String
}
