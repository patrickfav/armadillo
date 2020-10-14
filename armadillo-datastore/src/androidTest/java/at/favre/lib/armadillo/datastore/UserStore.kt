package at.favre.lib.armadillo.datastore

import android.content.Context
import androidx.datastore.DataStore
import androidx.datastore.createDataStore
import kotlinx.coroutines.flow.Flow
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.protobuf.ProtoBuf

@ExperimentalSerializationApi
class UserStore(context: Context) {
  private val serializer = User.serializer()
  private val protobuf = ProtoBuf {}

  private val protocol = object : ProtobufProtocol<User> {

    override fun fromBytes(bytes: ByteArray): User =
        protobuf.decodeFromByteArray(serializer, bytes)

    override fun fromNothing(): User =
        User(name = "", email = "")

    override fun toBytes(data: User): ByteArray =
        protobuf.encodeToByteArray(serializer, data)
  }

  private val userSerializer: ArmadilloSerializer<User> =
      ArmadilloSerializer(
          context = context,
          protocol = protocol
      )

  private val store: DataStore<User> = context.createDataStore(
      fileName = "user.pb",
      serializer = userSerializer
  )

  suspend fun update(reduce: (User) -> User) {
    store.updateData { user -> reduce(user) }
  }

  val user: Flow<User>
    get() = store.data

}
