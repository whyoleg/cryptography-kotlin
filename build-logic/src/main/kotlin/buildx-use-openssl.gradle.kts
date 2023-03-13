import openssl.*

rootProject.apply<OpensslRootPlugin>()

extensions.create("openssl", OpensslExtension::class.java, rootProject)
