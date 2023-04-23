TODO Add some docs for


## Protobuf
### Kotlinx TODO

### [Wire](https://github.com/square/wire) TODO

```kotlin
plugins {
  // TODO add https://github.com/square/wire stuff
}
```

### Google protobuf

 If you are new to Google Protobuf library it can be hard to setup. If
 you want a quickstart config this should get everything you need going.

```kotlin
import com.google.protobuf.gradle.builtins
import com.google.protobuf.gradle.generateProtoTasks
import com.google.protobuf.gradle.protoc

plugins {
  id("com.android.library")
  // everything else…
  id("com.google.protobuf") version "0.8.13"
}



protobuf {
  protobuf.protoc {
    artifact = "com.google.protobuf:protoc:3.13.0"
  }
  protobuf.generateProtoTasks {
    all().forEach { task ->
      task.builtins {
        create("java").option("lite")
      }
    }
  }
}

dependencies {
  implementation("com.google.protobuf:protobuf-javalite:3.13.0")
}
```

Sample proto class.
```proto
syntax = "proto3";

option java_package = "at.favre.lib.armadillo.datastore";
option java_outer_classname = "EncryptedPreferencesProto";

message User {
    string name = 1;
    string email = 2;
}
```
