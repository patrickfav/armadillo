package at.favre.lib.armadillo.datastore

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.core.createDataStore
import kotlinx.coroutines.flow.Flow
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.protobuf.ProtoBuf
import java.io.File

@ExperimentalSerializationApi
class UserStore(private val context: Context) {
  companion object {
    private const val fileName = "user"
  }
  private val serializer = User.serializer()
  private val protobuf = ProtoBuf {}

  private val protocol = object : ProtobufProtocol<User> {

    override fun decode(bytes: ByteArray): User =
        protobuf.decodeFromByteArray(serializer, bytes)

    override fun default(): User =
        User(name = "", email = "")

    override fun encode(data: User): ByteArray =
        protobuf.encodeToByteArray(serializer, data)
  }

  private val userSerializer: ArmadilloSerializer<User> =
      ArmadilloSerializer(
          context = context,
          protocol = protocol
      )

  private val store: DataStore<User> = context.createDataStore(
      fileName = fileName,
      serializer = userSerializer
  )

  suspend fun update(reduce: (User) -> User) {
    store.updateData { user -> reduce(user) }
  }

  val user: Flow<User>
    get() = store.data

  fun clear() {
    with(context) {
      val dataStore = File(this.filesDir, "datastore/$fileName")
      if(dataStore.exists()) {
        dataStore.delete()
      }
    }
  }

}
