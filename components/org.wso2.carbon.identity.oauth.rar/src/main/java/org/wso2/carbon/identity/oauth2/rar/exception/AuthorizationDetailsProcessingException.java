package org.wso2.carbon.identity.oauth2.rar.exception;

/**
 *
 */
public class AuthorizationDetailsProcessingException extends RuntimeException {

    private static final long serialVersionUID = -206212512259482200L;

    /**
     * Constructs a new exception with an error message.
     *
     * @param message The detail message.
     */
    public AuthorizationDetailsProcessingException(String message) {

        super(message);
    }

    /**
     * Constructs a new exception with the message and cause.
     *
     * @param message The detail message.
     * @param cause   The cause.
     */
    public AuthorizationDetailsProcessingException(String message, Throwable cause) {

        super(message, cause);
    }
}
