/*
 * Copyright (c) 2025, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.rar.validator;

import org.wso2.carbon.identity.oauth.rar.exception.AuthorizationDetailsProcessingException;
import org.wso2.carbon.identity.oauth.rar.model.AuthorizationDetails;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ServerException;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.validators.OAuth2TokenValidationMessageContext;

/**
 * Interface for validating {@link AuthorizationDetails} in different OAuth2 message contexts.
 *
 * <p>This interface provides methods to validate {@link AuthorizationDetails} across various OAuth2 message contexts,
 * including authorization requests, token requests, and token validation requests. Implementations of this
 * interface should handle the validation logic specific to the type of request and ensure that the returned
 * AuthorizationDetails are accurate and compliant with the application's security policies.</p>
 */
public interface AuthorizationDetailsValidator {

    /**
     * Validates and returns the {@link AuthorizationDetails} for the given {@link OAuthAuthzReqMessageContext}.
     * <p>
     * Validates the {@link AuthorizationDetails} during the authorization request phase.
     * This is typically invoked when an authorization request is received and needs to be processed.
     *
     * @param oAuthAuthzReqMessageContext The OAuth authorization request message context.
     * @return The validated {@link AuthorizationDetails}.
     * @throws AuthorizationDetailsProcessingException If an error occurs during the processing of authorization details
     * @throws IdentityOAuth2ServerException           if the validation fails due to a server error.
     */
    AuthorizationDetails getValidatedAuthorizationDetails(OAuthAuthzReqMessageContext oAuthAuthzReqMessageContext)
            throws AuthorizationDetailsProcessingException, IdentityOAuth2ServerException;

    /**
     * Validates and returns the {@link AuthorizationDetails} for the given {@link OAuthTokenReqMessageContext}.
     * <p>
     * Validates the AuthorizationDetails during the token request phase. This is usually called when an authorization
     * code is exchanged for an access token, or when a refresh token request is made.
     *
     * @param oAuthTokenReqMessageContext The OAuth token request message context.
     * @return The validated {@link AuthorizationDetails}.
     * @throws AuthorizationDetailsProcessingException If an error occurs during the processing of authorization details
     * @throws IdentityOAuth2ServerException           if the validation fails due to a server error.
     */
    AuthorizationDetails getValidatedAuthorizationDetails(OAuthTokenReqMessageContext oAuthTokenReqMessageContext)
            throws AuthorizationDetailsProcessingException, IdentityOAuth2ServerException;

    /**
     * Validates and returns the {@link AuthorizationDetails} for the given {@link OAuth2TokenValidationMessageContext}.
     * <p>
     * Validates the {@link AuthorizationDetails} during the token validation phase. This method is often used when an
     * access token is being introspected to ensure its legitimacy and the associated AuthorizationDetails.
     *
     * @param oAuth2TokenValidationMessageContext The OAuth2 token validation message context.
     * @return The validated {@link AuthorizationDetails}.
     * @throws AuthorizationDetailsProcessingException If an error occurs during the processing of authorization details
     * @throws IdentityOAuth2ServerException           If an error occurs related to the OAuth2 server.
     */
    AuthorizationDetails getValidatedAuthorizationDetails(OAuth2TokenValidationMessageContext
                                                                  oAuth2TokenValidationMessageContext)
            throws AuthorizationDetailsProcessingException, IdentityOAuth2ServerException;
}
