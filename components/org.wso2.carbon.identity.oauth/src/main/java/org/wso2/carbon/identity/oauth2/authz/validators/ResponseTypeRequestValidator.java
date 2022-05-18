/*
 * Copyright (c) 2022, WSO2 Inc. (http://www.wso2.com).
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.authz.validators;

import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthRequestException;
import org.wso2.carbon.identity.oauth2.dto.OAuth2ClientValidationResponseDTO;

import javax.servlet.http.HttpServletRequest;

/**
 * Validator interface for OAuth 2 response types. This will validate the inputs from the client.
 */
public interface ResponseTypeRequestValidator {

    /**
     * Get the response type.
     *
     * @return  Response type.
     */
    String getResponseType();

    /**
     * Check Whether the provided inputs from the client satisfy the response type validation
     *
     * @param request      The HttpServletRequest front the client.
     * @throws InvalidOAuthRequestException InvalidOAuthRequestException.
     */
    void validateInputParameters(HttpServletRequest request) throws InvalidOAuthRequestException;

    /**
     * Check Whether the provided client information satisfy the response type validation
     *
     * @param request      The HttpServletRequest front the client.
     * @return <code>OAuth2ClientValidationResponseDTO</code> bean with validity information,
     * callback, App Name, Error Code and Error Message when appropriate.
     */
    OAuth2ClientValidationResponseDTO validateClientInfo(HttpServletRequest request);
}
