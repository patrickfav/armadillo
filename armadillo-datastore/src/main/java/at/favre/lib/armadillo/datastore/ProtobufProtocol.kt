package at.favre.lib.armadillo.datastore

/**
 * The protocol is used to wrap the encoded/decode for any protobuff implementation.
 *
 * Datastore requies the type T MUST be immutable. Any mutable types will result in a broken DataStore.
 *
 * Datastore will always return an empty
 */
interface ProtobufProtocol<T> {
  /**
   * un-encrypted proto byte encoding of [T]
   */
  fun encode(data: T): ByteArray

  /**
   * un-encrypted proto bytes to proto class of [T]
   */
  fun decode(bytes: ByteArray): T

  /**
   * Returns a default value when the store is empty. This will
   * always happen on first read even when writing to the store 
   * for the first time.
   */
  fun default(): T
}
