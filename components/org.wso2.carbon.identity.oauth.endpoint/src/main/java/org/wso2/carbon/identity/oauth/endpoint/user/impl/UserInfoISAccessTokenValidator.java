/*
 * Copyright (c) 2013, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
package org.wso2.carbon.identity.oauth.endpoint.user.impl;

import org.apache.commons.lang.ArrayUtils;
import org.apache.oltu.oauth2.common.error.OAuthError;
import org.wso2.carbon.identity.oauth.endpoint.util.EndpointUtil;
import org.wso2.carbon.identity.oauth.user.UserInfoAccessTokenValidator;
import org.wso2.carbon.identity.oauth.user.UserInfoEndpointException;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationRequestDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationResponseDTO;

import java.util.Arrays;
import javax.servlet.http.HttpServletRequest;

import static org.wso2.carbon.identity.oauth2.util.OAuth2Util.isValidTokenBinding;

/**
 * This class validates the access token using the IS token validation end point
 */
public class UserInfoISAccessTokenValidator implements UserInfoAccessTokenValidator {

    /**
     * Validates the access token with WSO2 IS token validation OSGI service.
     * Scope is checked.
     */
    @Override
    public OAuth2TokenValidationResponseDTO validateToken(String accessTokenIdentifier)
            throws UserInfoEndpointException {

        return validateToken(accessTokenIdentifier, null);
    }

    @Override
    public OAuth2TokenValidationResponseDTO validateToken(String accessTokenIdentifier, HttpServletRequest request)
            throws UserInfoEndpointException {

        OAuth2TokenValidationRequestDTO dto = new OAuth2TokenValidationRequestDTO();
        OAuth2TokenValidationRequestDTO.OAuth2AccessToken accessToken = dto.new OAuth2AccessToken();
        accessToken.setTokenType("bearer");
        accessToken.setIdentifier(accessTokenIdentifier);
        dto.setAccessToken(accessToken);
        OAuth2TokenValidationResponseDTO response = EndpointUtil.getOAuth2TokenValidationService().validate(dto);

        // invalid access token
        if (!response.isValid()) {
            throw new UserInfoEndpointException(OAuthError.ResourceResponse.INVALID_TOKEN,
                    "Access token validation failed");
        }

        // check the scope
        boolean hasOpenIDScope = false;
        String[] scopes = response.getScope();
        if (ArrayUtils.isNotEmpty(scopes)) {
            hasOpenIDScope = Arrays.asList(scopes).contains("openid");
        }

        if (!hasOpenIDScope) {
            throw new UserInfoEndpointException(OAuthError.ResourceResponse.INSUFFICIENT_SCOPE,
                    "Access token does not have the openid scope");
        }

        if (response.getAuthorizedUser() == null) {
            throw new UserInfoEndpointException(OAuthError.ResourceResponse.INVALID_TOKEN,
                    "Access token is not valid. No authorized user found. Invalid grant");
        }

        if (request != null && !isValidTokenBinding(response.getTokenBinding(), request)) {
            throw new UserInfoEndpointException(OAuthError.ResourceResponse.INVALID_REQUEST,
                    "Valid token binding value not present in the request.");
        }

        OAuth2TokenValidationResponseDTO.AuthorizationContextToken authorizationContextToken = response.new AuthorizationContextToken(
                accessToken.getTokenType(), accessToken.getIdentifier());
        response.setAuthorizationContextToken(authorizationContextToken);
        return response;
    }
}
