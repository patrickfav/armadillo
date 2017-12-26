package at.favre.lib.securepref;

/**
 * @since 26.12.2017
 */

public interface RecoveryPolicy {

    boolean shouldThrowRuntimeException();

    boolean shouldRemoveBrokenContent();

    final class Default implements RecoveryPolicy {
        private final boolean throwRuntimeException;
        private final boolean removeBrokenContent;

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
