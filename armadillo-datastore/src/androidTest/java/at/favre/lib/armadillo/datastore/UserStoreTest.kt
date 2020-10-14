package at.favre.lib.armadillo.datastore

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.ExperimentalSerializationApi
import org.junit.Test
import org.junit.runner.RunWith

@ExperimentalSerializationApi
@RunWith(AndroidJUnit4::class)
class UserStoreTest {

  @Test
  fun canReadEmptyUserFromStore() {
    val store = UserStore(ApplicationProvider.getApplicationContext())

    val user = runBlocking { store.user.first() }

    assert(user.name == "")
    assert(user.email == "")
  }


  @Test
  fun canUserStore_andReadFromStore() {
    val store = UserStore(ApplicationProvider.getApplicationContext())
    val newName = "new name"

    runBlocking {
      store.update {
        it.copy(name = newName)
      }
    }
    val user = runBlocking { store.user.first() }

    assert(user.name == newName)
    assert(user.email == "")
  }
}
