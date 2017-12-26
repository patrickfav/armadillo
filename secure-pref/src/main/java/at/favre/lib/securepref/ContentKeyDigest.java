package at.favre.lib.securepref;

/**
 * @author RISE GmbH (patrick.favre@rise-world.com)
 * @since 26.12.2017
 */

public interface ContentKeyDigest {
    String derive(String key, String usageName);
}
