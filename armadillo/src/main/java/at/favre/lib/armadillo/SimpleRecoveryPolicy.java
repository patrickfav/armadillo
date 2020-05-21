package at.favre.lib.armadillo;

import androidx.annotation.NonNull;

/**
 * Simple implementation of a {@link RecoveryPolicy} that supports removing data
 * and throwing exceptions.
 *
 * @author Patrick Favre-Bulle
 */

public abstract class SimpleRecoveryPolicy implements RecoveryPolicy {

    /**
     * If the content cannot be read (or written) defines if a runtime exception should be thrown (
     * i.e. the calle has to handle the error)
     *
     * @return if exception should be thrown
     */
    abstract boolean shouldThrowRuntimeException();

    /**
     * If the content should be automatically removed when it cannot be read.
     *
     * @return if content should be removed
     */
    abstract boolean shouldRemoveBrokenContent();

    @Override
    public void handleBrokenContent(EncryptionProtocolException e, String keyHash, @NonNull String base64Encrypted,
                                    boolean userPasswordUsed, ArmadilloSharedPreferences sharedPreferences) throws SecureSharedPreferenceCryptoException {
        if (shouldRemoveBrokenContent()) {
            sharedPreferences.edit().remove(keyHash).apply();
        }
        if (shouldThrowRuntimeException()) {
            throw new SecureSharedPreferenceCryptoException("could not decrypt " + keyHash, e);
        }
    }

    /**
     * Default implementation
     */
    public static final class Default extends SimpleRecoveryPolicy {
        private final boolean throwRuntimeException;
        private final boolean removeBrokenContent;

        @SuppressWarnings("WeakerAccess")
        public Default(boolean throwRuntimeException, boolean removeBrokenContent) {
            this.throwRuntimeException = throwRuntimeException;
            this.removeBrokenContent = removeBrokenContent;
        }

        @Override
        public boolean shouldThrowRuntimeException() {
            return throwRuntimeException;
        }

        @Override
        public boolean shouldRemoveBrokenContent() {
            return removeBrokenContent;
        }
    }
}
