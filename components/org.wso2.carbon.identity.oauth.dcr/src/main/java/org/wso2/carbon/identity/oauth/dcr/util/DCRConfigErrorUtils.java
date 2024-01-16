package org.wso2.carbon.identity.oauth.dcr.util;

import org.wso2.carbon.identity.oauth.dcr.DCRConfigErrorMessage;
import org.wso2.carbon.identity.oauth.dcr.exception.DCRMClientException;
import org.wso2.carbon.identity.oauth.dcr.exception.DCRMServerException;

/**
 * Error utilities related to DCR Configurations.
 */
public class DCRConfigErrorUtils {

    /**
     * Handle server exceptions.
     *
     * @param error The ErrorMessage.
     * @param data  Additional data that should be added to the error message. This is a String var-arg.
     * @return DCRMServerException instance.
     */
    public static DCRMServerException handleServerException(DCRConfigErrorMessage error, String... data) {

        return new DCRMServerException(String.format(error.getDescription(), data), error.getCode());
    }

    /**
     * Handle server exceptions.
     *
     * @param error The ErrorMessage.
     * @param e     Original error.
     * @param data  Additional data that should be added to the error message. This is a String var-arg.
     * @return DCRMServerException instance.
     */
    public static DCRMServerException handleServerException(DCRConfigErrorMessage error, Throwable e, String... data) {

        return new DCRMServerException(String.format(error.getDescription(), data), error.getCode(), e);
    }

    /**
     * Handle client exceptions.
     *
     * @param error The ErrorMessage.
     * @param data  Additional data that should be added to the error message. This is a String var-arg.
     * @return DCRMClientException instance.
     */
    public static DCRMClientException handleClientException(DCRConfigErrorMessage error, String... data) {

        return new DCRMClientException(String.format(error.getDescription(), data), error.getCode());
    }

    /**
     * Handle client exceptions.
     *
     * @param error The ErrorMessage.
     * @param e     Original error.
     * @param data  Additional data that should be added to the error message. This is a String var-arg.
     * @return DCRMClientException instance.
     */
    public static DCRMClientException handleClientException(DCRConfigErrorMessage error, Throwable e, String... data) {

        return new DCRMClientException(String.format(error.getDescription(), data), error.getCode(), e);
    }
}
