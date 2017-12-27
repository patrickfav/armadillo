package at.favre.lib.armadillo;

/**
 * A hash function to convert a string and usage name to a string representation
 * of a hash.
 *
 * @author Patrick Favre-Bulle
 */

public interface StringMessageDigest {
    /**
     * Derives given key given by the caller with given usage description to a hash
     *
     * @param providedMessage the message provided by the caller to generate the hash for
     * @param usageName       a simple description for what this is (e.g. "contentKey", "prefName",... )
     * @return a hash derived from providedMessage + usageName
     */
    String derive(String providedMessage, String usageName);
}
