package at.favre.lib.armadillo;

/**
 *
 * @since 26.12.2017
 */

public interface ContentKeyDigest {
    String derive(String key, String usageName);
}
