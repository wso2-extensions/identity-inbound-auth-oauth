package org.wso2.carbon.identity.oauth2.validators.validationhandler;

/**
 * ScopeValidatorPolicyHandlerException
 */
public class ScopeValidationHandlerException extends Exception {

    /**
     * Constructs a new exception with an error message.
     *
     * @param message The detail message.
     */
    public ScopeValidationHandlerException(String message) {

        super(message);
    }

    /**
     * Constructs a new exception with the message and cause.
     *
     * @param message The detail message.
     * @param cause The cause.
     */
    public ScopeValidationHandlerException(String message, Throwable cause) {

        super(message, cause);
    }
}
