package at.favre.lib.armadillo;

/**
 * Defines how the storage should behave on errors
 *
 * @author Patrick Favre-Bulle
 */

public interface RecoveryPolicy {

    /**
     * If the content cannot be read (or written) defines if a runtime exception should be thrown (
     * i.e. the calle has to handle the error)
     *
     * @return if exception should be thrown
     */
    boolean shouldThrowRuntimeException();

    /**
     * If the content should be automatically removed when it cannot be read.
     *
     * @return if content should be removed
     */
    boolean shouldRemoveBrokenContent();

    /**
     * Default implementation
     */
    final class Default implements RecoveryPolicy {
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
