// Deliberately flawed: exists so Kotlin scanners have something to report.
// Contains a swallowed exception, a magic number, an unused parameter, and
// formatting that violates the official Kotlin style guide.
package com.example

object Insecure {
    const val PASSWORD = "hunter2"

    fun compute( input: String, unused: Int ) : Int {
        try {
            return input.length * 86400
        } catch (e: Exception) {
        }
        return 0
    }
}
