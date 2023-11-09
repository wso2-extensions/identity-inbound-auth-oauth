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
import org.wso2.carbon.identity.oauth.endpoint.api.auth.model.APIError;

import java.util.Optional;

import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.Response;

/**
 * Utility class for authentication API.
 */
public class ApiAuthnUtils {

    private static final Log LOG = LogFactory.getLog(ApiAuthnUtils.class);

    private ApiAuthnUtils() {

    }

    /**
     * Build response for client error.
     *
     * @param exception AuthServiceClientException.
     * @return Client error response.
     */
    public static Response buildResponseForClientError(AuthServiceClientException exception) {

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
        if (exception.getMessage() != null) {
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
     * @return Server error response.
     */
    public static Response buildResponseForServerError(AuthServiceException exception) {

        APIError apiError = new APIError();
        Optional<AuthServiceConstants.ErrorMessage> error =
                AuthServiceConstants.ErrorMessage.fromCode(exception.getErrorCode());

        if (error.isPresent()) {
            apiError.setCode(error.get().code());
            apiError.setMessage(error.get().message());
            apiError.setDescription(error.get().description());
        } else {
            String errorCode =
                    exception.getErrorCode() != null ? exception.getErrorCode() : getDefaultServerError().code();
            apiError.setCode(errorCode);
            apiError.setMessage(getDefaultServerError().message());
            apiError.setDescription(getDefaultServerError().description());
        }
        apiError.setTraceId(getCorrelationId());
        String jsonString = new Gson().toJson(apiError);
        return Response.status(HttpServletResponse.SC_INTERNAL_SERVER_ERROR).entity(jsonString).build();
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
