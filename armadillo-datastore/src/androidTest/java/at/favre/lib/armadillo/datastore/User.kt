package at.favre.lib.armadillo.datastore

import kotlinx.serialization.Serializable

@Serializable
data class User(
    val name: String,
    val email: String,
)
