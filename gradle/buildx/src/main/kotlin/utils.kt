import org.gradle.api.*
import org.gradle.api.artifacts.*
import org.gradle.api.file.*
import org.gradle.kotlin.dsl.*

fun SourceDirectorySet.dir(path: String) = setSrcDirs(listOf(path))
