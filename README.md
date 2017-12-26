# Armadillo - Encrypted Shared Preference

Armadillo is an implementation of encrypted shared preferences.


## Features

* **No-Nonse-Crypto**: Uses [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)-[GCM](https://en.wikipedia.org/wiki/Galois/Counter_Mode), [Bcrypt](https://en.wikipedia.org/wiki/Bcrypt) and [HKDF](https://en.wikipedia.org/wiki/HKDF)
* **Flexible**: Tons of nobs and switches while having sane defaults
* **Modular**: use your own implementation of symmetric cipher, key stretching, data obfuscation, etc.

## Quick Start

Add the following to your dependencies ([add jcenter to your repositories](https://developer.android.com/studio/build/index.html#top-level) if you haven't)

```gradle
compile 'at.favre.lib:armadillo:x.y.z'
```

A very minimal example

```java
    SharedPreferences preferences = Armadillo.create(context, "myPrefs")
        .encryptionFingerprint(context)
        .build();

    preferences.edit().putString("key1", "string").apply();
    String s = preferences.getString("key1", null);
```

## Digital Signatures

### Signed Commits

All tags and commits by me are signed with git with my private key:

    GPG key ID: 4FDF85343912A3AB
    Fingerprint: 2FB392FB05158589B767960C4FDF85343912A3AB

## Build

Assemble the lib with the following command

    ./gradlew :armadillo:assemble

The `.aar` files can then be found in `/armadillo/build/outputs/aar` folder

## Libraries & Credits

* [jBcrypt](https://github.com/jeremyh/jBCrypt)
* [Icon by Freepik](https://www.flaticon.com/free-icon/armadillo_371647#term=armadillo&page=1&position=4)

## Similar Projects:

* [secure-preferences using AES-CBC](https://github.com/scottyab/secure-preferences)
* [secure-preferences supporting Android Keystore System](https://github.com/ophio/secure-preferences)
* [secure-preferences using FB Conceal framework](https://github.com/KaKaVip/secure-preferences)

# License

Copyright 2017 Patrick Favre-Bulle

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
