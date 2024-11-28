package org.wso2.carbon.identity.oauth2.rar.exception;

import org.wso2.carbon.identity.base.IdentityException;

/**
 * Exception class to represent failures related to Rich Authorization Requests in OAuth 2.0 clients.
 *
 * <p>This exception is thrown when there are errors in processing authorization details during the OAuth 2.0
 * authorization flow. It extends the {@link IdentityException} class, providing more specific
 * context for authorization-related issues.</p>
 */
public class AuthorizationDetailsProcessingException extends IdentityException {

    private static final long serialVersionUID = -206212512259482200L;

    /**
     * Constructs a new exception with the specified detail message.
     *
     * @param message The detail message. It provides information about the cause of the exception.
     */
    public AuthorizationDetailsProcessingException(final String message) {

        super(message);
    }

    /**
     * Constructs a new exception with the specified detail message and cause.
     *
     * @param message The detail message. It provides information about the cause of the exception.
     * @param cause   The cause of the exception. It can be used to retrieve the stack trace or other information
     *                about the root cause of the exception.
     */
    public AuthorizationDetailsProcessingException(final String message, final Throwable cause) {

        super(message, cause);
    }
}
