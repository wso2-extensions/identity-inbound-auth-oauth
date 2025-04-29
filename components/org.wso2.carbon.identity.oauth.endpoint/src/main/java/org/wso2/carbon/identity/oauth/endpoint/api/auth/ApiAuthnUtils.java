/*
 * Copyright (c) 2023, WSO2 LLC. (https://www.wso2.com) All Rights Reserved.
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.endpoint.api.auth;

import com.google.gson.Gson;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.slf4j.MDC;
import org.wso2.carbon.identity.application.authentication.framework.exception.auth.service.AuthServiceClientException;
import org.wso2.carbon.identity.application.authentication.framework.exception.auth.service.AuthServiceException;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authentication.framework.util.auth.service.AuthServiceConstants;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.endpoint.api.auth.model.APIError;
import org.wso2.carbon.identity.oauth.endpoint.util.EndpointUtil;

import java.util.Optional;

import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.Response;

/**
 * Utility class for authentication API.
 */
public class ApiAuthnUtils {

    private static final Log LOG = LogFactory.getLog(ApiAuthnUtils.class);
    private static final String AUTHZ_FAILURE_ERROR_CODE = "401";
    private static final String AUTHZ_FAILURE_ERROR_MESSAGE = "Unauthorized";
    private static final String AUTHZ_FAILURE_ERROR_DESCRIPTION = "Authorization failure. Authorization information " +
            "was invalid or missing from your request.";

    private ApiAuthnUtils() {

    }

    /**
     * Build response for client error.
     *
     * @param exception AuthServiceClientException.
     * @param log Log object.
     * @return Client error response.
     */
    public static Response buildResponseForClientError(AuthServiceClientException exception, Log log) {

        if (log.isDebugEnabled()) {
            log.debug("Client error while handling authentication request.", exception);
        }

        APIError apiError = new APIError();
        Optional<AuthServiceConstants.ErrorMessage> error =
                AuthServiceConstants.ErrorMessage.fromCode(exception.getErrorCode());

        String errorCode = exception.getErrorCode() != null ? exception.getErrorCode() : getDefaultClientError().code();

        String errorMessage;
        if (error.isPresent()) {
            errorMessage = error.get().message();
        } else {
            errorMessage = getDefaultClientError().message();
        }

        String errorDescription;
        if (StringUtils.isNotBlank(exception.getMessage())) {
            errorDescription = exception.getMessage();
        } else {
            if (error.isPresent()) {
                errorDescription = error.get().description();
            } else {
                errorDescription = getDefaultClientError().description();
            }
        }

        apiError.setCode(errorCode);
        apiError.setMessage(errorMessage);
        apiError.setDescription(errorDescription);
        apiError.setTraceId(getCorrelationId());
        String jsonString = new Gson().toJson(apiError);
        return Response.status(HttpServletResponse.SC_BAD_REQUEST).entity(jsonString).build();
    }

    /**
     * Build response for server error.
     *
     * @param exception AuthServiceException.
     * @param log Log object.
     * @return Server error response.
     */
    public static Response buildResponseForServerError(AuthServiceException exception, Log log) {

        int httpStatusCode = HttpServletResponse.SC_INTERNAL_SERVER_ERROR;
        boolean isUnSupportedAuthenticatorError = StringUtils.equals(exception.getErrorCode(),
                AuthServiceConstants.ErrorMessage.ERROR_AUTHENTICATOR_NOT_SUPPORTED.code());

        if (isUnSupportedAuthenticatorError) {
            /* Unsupported authenticator error can be triggered by the client
             if an unsupported authenticator is configured in the server.
             Therefore, we log this error as a debug log.*/
            if (log.isDebugEnabled()) {
                log.debug("Unsupported authenticator error while handling authentication request.", exception);
            }
        } else {
            log.error("Error while handling authentication request.", exception);
        }

        if (isUnSupportedAuthenticatorError) {
            httpStatusCode = HttpServletResponse.SC_NOT_IMPLEMENTED;
        }
        APIError apiError = new APIError();
        Optional<AuthServiceConstants.ErrorMessage> error =
                AuthServiceConstants.ErrorMessage.fromCode(exception.getErrorCode());

        if (error.isPresent()) {
            apiError.setCode(error.get().code());
            apiError.setMessage(error.get().message());

            // If an exception is sent with a known error code the error message will contain additional information.
            String errorDescription = error.get().description();
            if (StringUtils.isNotBlank(errorDescription)) {
                errorDescription = exception.getMessage();
            }
            apiError.setDescription(errorDescription);
        } else {
            String errorCode =
                    exception.getErrorCode() != null ? exception.getErrorCode() : getDefaultServerError().code();
            apiError.setCode(errorCode);
            apiError.setMessage(getDefaultServerError().message());
            apiError.setDescription(getDefaultServerError().description());
        }
        apiError.setTraceId(getCorrelationId());
        String jsonString = new Gson().toJson(apiError);
        return Response.status(httpStatusCode).entity(jsonString).build();
    }

    /**
     * Build response for authorization failure.
     *
     * @param description Error description.
     * @param log Log object.
     * @return Authorization failure response.
     */
    public static Response buildResponseForAuthorizationFailure(String description, Log log) {

        if (log.isDebugEnabled()) {
            log.debug("Request authorization failed. " + description);
        }

        APIError apiError = new APIError();
        apiError.setCode(AUTHZ_FAILURE_ERROR_CODE);
        apiError.setMessage(AUTHZ_FAILURE_ERROR_MESSAGE);
        if (StringUtils.isNotBlank(description)) {
            apiError.setDescription(description);
        } else {
            apiError.setDescription(AUTHZ_FAILURE_ERROR_DESCRIPTION);
        }
        apiError.setTraceId(getCorrelationId());
        String jsonString = new Gson().toJson(apiError);

        return Response.status(HttpServletResponse.SC_UNAUTHORIZED)
                .header(OAuthConstants.HTTP_RESP_HEADER_AUTHENTICATE, EndpointUtil.getRealmInfo())
                .entity(jsonString).build();
    }

    /**
     * Get correlation id of current thread.
     * If the correlation id is not present in the log MDC, an empty string is returned.
     *
     * @return correlation-id
     */
    public static String getCorrelationId() {

        String ref;
        if (isCorrelationIDPresent()) {
            ref = MDC.get(FrameworkUtils.CORRELATION_ID_MDC);
        } else {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Correlation id is not present in the log MDC.");
            }
            ref = StringUtils.EMPTY;
        }
        return ref;
    }

    private static boolean isCorrelationIDPresent() {

        return MDC.get(FrameworkUtils.CORRELATION_ID_MDC) != null;
    }

    private static AuthServiceConstants.ErrorMessage getDefaultClientError() {

        return AuthServiceConstants.ErrorMessage.ERROR_INVALID_AUTH_REQUEST;
    }

    private static AuthServiceConstants.ErrorMessage getDefaultServerError() {

        return AuthServiceConstants.ErrorMessage.ERROR_UNABLE_TO_PROCEED;
    }
}
