# Releases

## v0.6.0 (WIP)

* [Security] Fix bcrypt implementation #16, #8
* Add change password feature #13, #22
* Add change key stretching feature #16

> [Full changelog](https://github.com/patrickfav/armadillo/compare/v0.5.0...v0.6.0)

## v0.5.0 (11/07/18) - Important Security Fix

* [Security] A user provided password was NOT used for the creation of the secret key #11 (thx @davidmigloz) 
* Various small fixes cleaning memory from security relevant data (internal keys, salts, etc.)
* Fix minSdk to be 19 instead of 21
* New logo (thx @iqbalhood)

> [Full changelog](https://github.com/patrickfav/armadillo/compare/v0.4.3...v0.5.0)

### Known Issues

* Currently the AES mode GCM does not work correctly on Kitkat, working on a fix
* Currently migration is needed if user password was used (will add a migration guide later)

**Note:** If you are using 0.4.x of armadillo, the user password will not encrypt the data. Please update ASAP, but mind that this might make data inaccessible. I will be working on a workaround/migration guide. (see #11)

## v0.4.3 (14/06/18)

* Better exception clean up with resources and some byte wipe

> [Full changelog](https://github.com/patrickfav/armadillo/compare/v0.4.2...v0.4.3)

**Note:** This release has a known security issue relating to the user password not correctly used during encryption (see #11). Do not use this release and migrate to 0.5+ ASAP.

## v0.4.2 (20/04/18)

* Supporting `null` in `.putString()` and `.putStringSet()`; same as calling `remove()` as per API spec

> [Full changelog](https://github.com/patrickfav/armadillo/compare/v0.4.1...v0.4.2)

## v0.4.1 (20/04/18)

* Fixes missing using incorrect dependency type '.aar'

> [Full changelog](https://github.com/patrickfav/armadillo/compare/v0.4.0...v0.4.1)

## v0.4.0 (28/03/18)

* Fixes missing transitive dependency in pom

> [Full changelog](https://github.com/patrickfav/armadillo/compare/v0.3.0...v0.4.0)

**Note:** This release has a bug in the pom dependency file.

## v0.3.0 (08/01/18)

* Add compressor feature
* Fixes issue were storage salt was incorrectly created

> [Full changelog](https://github.com/patrickfav/armadillo/compare/v0.2.0...v0.3.0)

**Note:** misses transitive dependencies.

## v0.2.0 (03/01/18)

* Add authenticated encryption additional associated data
* Add crypto protocol version

> [Full changelog](https://github.com/patrickfav/armadillo/compare/eedc283f0b8e1b658d01afd2a9d9b3dedac0fd33...v0.2.0)

**Note:** This version has fatal flaw not correctly persisting the storage random making it impossible to retrieve the data after recreating the shared preferences.

## v0.1.0 (19/12/17)

* Initial release
