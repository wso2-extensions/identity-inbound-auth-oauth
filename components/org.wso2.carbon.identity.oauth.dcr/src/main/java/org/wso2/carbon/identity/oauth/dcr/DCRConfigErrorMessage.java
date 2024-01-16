package org.wso2.carbon.identity.oauth.dcr;

/**
 * Error Message class for DCR Configuration errors.
 */
public enum DCRConfigErrorMessage {

    /**
     * Invalid tenant domain.
     * TODO: check if this is the right error code
     */
    ERROR_CODE_INVALID_TENANT_DOMAIN("60004",
            "Invalid input.",
            "%s is not a valid tenant domain."),

    /**
     * Unable to retrieve DCR configuration.
     */
    ERROR_CODE_DCR_CONFIG_RETRIEVE("65017",
            "Unable to retrieve DCR configuration.",
            "Server encountered an error while retrieving the " +
                    "DCR configuration of %s.");

    /**
     * The error code.
     */
    private final String code;

    /**
     * The error message.
     */
    private final String message;

    /**
     * The error description.
     */
    private final String description;


    DCRConfigErrorMessage(String code, String message, String description) {
        this.code = code;
        this.message = message;
        this.description = description;
    }

    /**
     * Get the {@code code}.
     *
     * @return Returns the {@code code} to be set.
     */
    public String getCode() {

        return code;
    }

    /**
     * Get the {@code message}.
     *
     * @return Returns the {@code message} to be set.
     */
    public String getMessage() {

        return message;
    }

    /**
     * Get the {@code description}.
     *
     * @return Returns the {@code description} to be set.
     */
    public String getDescription() {

        return description;
    }

    @Override
    public String toString() {

        return code + ":" + message;
    }
}
