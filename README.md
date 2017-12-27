# Armadillo - Encrypted Shared Preference

Armadillo is an implementation of encrypted shared preferences.

[![Download](https://api.bintray.com/packages/patrickfav/maven/armadillo/images/download.svg) ](https://bintray.com/patrickfav/maven/armadillo/_latestVersion)
[![Build Status](https://travis-ci.org/patrickfav/armadillo.svg?branch=master)](https://travis-ci.org/patrickfav/armadillo)


## Features

* **No-Nonse-Crypto**: Uses [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)-[GCM](https://en.wikipedia.org/wiki/Galois/Counter_Mode), [Bcrypt](https://en.wikipedia.org/wiki/Bcrypt) and [HKDF](https://en.wikipedia.org/wiki/HKDF)
* **Flexible**: Tons of nobs and switches while having sane defaults
* **Modular**: use your own implementation of symmetric cipher, key stretching, data obfuscation, etc.
* **Lightweight**: No massive dependencies required like [BouncyCastle](https://www.bouncycastle.org/) or [Facebook Conceal](https://github.com/facebook/conceal)

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

## Description

## Persistence Profile

### Key

The key is hashed with [HKDF](https://en.wikipedia.org/wiki/HKDF) (which uses
Hmac with Sha512 internally) expanded to a 20 byte hash which will be encoded with
[base16 (hex)](https://en.wikipedia.org/wiki/Hexadecimal). The key generation
is salted by the encryption fingerprint, so different shared preferences will
generate different hashes for the same keys.

### Content

The diagram below illustrates the used data format. To disguise the format
a little bit it will be obfuscated by a simple xor cipher.

![screenshot gallery](doc/persistence_profile.png)

The resulting data will be encoded with [base64](https://en.wikipedia.org/wiki/Base64) and looks like this in the shared preferences xml:

```xml
<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <string name="39e3e4f83dda81c44f8a9063196b28b3d5091fca">hwbchXlqDAQcig6q3UWxdbOb2wouDGGwjUGNIzREiy0=</string>
    <string name="62ef41ac992322bdd669e96799c12a66a2cce111">IOIpvllJPY+aIwv+Z+w+SSJLxHD218vOUpd+e10eCczZURrNSN8h49V+Oy3thjEsbp/2zuqa6uNlGJ8tMpgk/uU0b+iLIciN+0EGYLKso6UYgbtgH/3n9GcQzqOvAIZvZeuurk4f9x9gL3fknHpFaXSIOYrSGZOjwD8WnOk1w2/tSufyZNSIdxUGvjniwpNaeawACi1EKitA4Oj+GRZRjW5NFY3jpYlzDPw=</string>
</map>
```

### Design Choices

* **AES + GCM block mode:** To make sure that the data is not only kept
confidential, but it's integrity also preserved, the authenticated encryption
[AES+GCM](https://en.wikipedia.org/wiki/Galois/Counter_Mode) is used. GCM
can be implemented efficiently and fast and is the usually alternative to
[encrypt then mac](https://en.wikipedia.org/wiki/Authenticated_encryption#Encrypt-then-MAC_(EtM))
with AES+CBC and HMAC. The authentication tag is appended to the message and
is 16 byte long in this implementation. A downside of GCM is the requirement
to [never reuse](https://en.wikipedia.org/wiki/Galois/Counter_Mode#Security)
 a [IV](https://en.wikipedia.org/wiki/Initialization_vector) with the same key,
 which is avoided in this lib.
* **KDFs with Key Stretching features for user passwords**
* **Minimum SDK 19 (Android 4.4):** A way to increase security is to cap older
implementation. SDK 19 seems to be a good compromise where most of the older
[security hack fixes](https://android-developers.googleblog.com/2013/08/some-securerandom-thoughts.html)
 are not necessary anymore, but still targeting most devices.
* **Use of [JCA as Provider](https://issuetracker.google.com/issues/36983155) for cryptographic primitives:**
Various security frameworks exists in Java: [BouncyCastle](https://www.bouncycastle.org/),
[Conscrypt](https://github.com/google/conscrypt), [Facebook Conceal](https://github.com/facebook/conceal).
The problem is that these libraries are usually huge and require manual
updates to have all the latents security fixes.
This library however depends on the default JCA provider (although the developer may choose a
different one). This puts trust in the device and it's implementation, while
expecting frequent security patches. Usually the default provider since KitKat is
[`AndroidOpenSSL`]() provider which is fast (probably hardware accelerated for e.g. AES) and
heavily used by e.g. TLS implementation.
* **[Android Keystore System](https://developer.android.com/training/articles/keystore.html) is not used:**
  In my humble opinion, the Android Keystore is the best possible way to secure
  data on an Android device. Unfortunately, due to the massive fragmentation
  in the ecosystem properly handling and using the Android Keystore System
  is not easy and has [some major drawbacks](https://issuetracker.google.com/issues/36983155).
  Due to working in a security relevant field I have a lot of expirence with
  this technology, therefore the decision was made to not support it.
* **Use of data obfuscation**

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
