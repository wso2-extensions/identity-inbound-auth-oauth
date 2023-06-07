/*
 * Copyright (c) 2023, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
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

package org.wso2.carbon.identity.oauth2.responsemode.provider.jarm.impl;

import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.responsemode.provider.AuthorizationResponseDTO;
import org.wso2.carbon.identity.oauth2.responsemode.provider.ResponseModeProvider;
import org.wso2.carbon.identity.oauth2.responsemode.provider.jarm.JarmResponseModeProvider;

/**
 * This class is used when response_mode = jwt is sent in the auth request.
 * It checks the response_type and decide which response_mode is to use and gets the relevant JarmResponseModeProvider.
 */
public class JwtResponseModeProvider extends JarmResponseModeProvider {

    private static final String RESPONSE_MODE = OAuthConstants.ResponseModes.JWT;
    private static final String FRAGMENT_JWT_RESPONSE_MODE = OAuthConstants.ResponseModes.FRAGMENT_JWT;
    private static final String QUERY_JWT_RESPONSE_MODE = OAuthConstants.ResponseModes.QUERY_JWT;

    @Override
    public String getResponseMode() {

        return RESPONSE_MODE;
    }

    @Override
    public String getAuthResponseRedirectUrl(AuthorizationResponseDTO authorizationResponseDTO) {

        String responseType = authorizationResponseDTO.getResponseType();
        String responseMode;

        if (hasIDTokenOrTokenInResponseType(responseType)) {
            responseMode =  FRAGMENT_JWT_RESPONSE_MODE;
        } else {
            responseMode =  QUERY_JWT_RESPONSE_MODE;
        }

        ResponseModeProvider responseModeProvider = OAuth2ServiceComponentHolder.getResponseModeProvider(responseMode);
        return responseModeProvider.getAuthResponseRedirectUrl(authorizationResponseDTO);
    }

    @Override
    public String getAuthResponseBuilderEntity(AuthorizationResponseDTO authorizationResponseDTO) {

        return null;
    }

    @Override
    public AuthResponseType getAuthResponseType() {

        return AuthResponseType.REDIRECTION;
    }

}
