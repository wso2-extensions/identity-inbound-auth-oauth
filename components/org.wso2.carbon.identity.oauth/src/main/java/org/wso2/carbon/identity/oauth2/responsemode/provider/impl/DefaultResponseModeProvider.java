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

package org.wso2.carbon.identity.oauth2.responsemode.provider.impl;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.responsemode.provider.AbstractResponseModeProvider;
import org.wso2.carbon.identity.oauth2.responsemode.provider.AuthorizationResponseDTO;
import org.wso2.carbon.identity.oauth2.responsemode.provider.ResponseModeProvider;

/**
 * This class is used as a fallback response mode provider when no other ResponseModeProvider can handle the provided
 * response_mode.
 * It checks the response_type and decide which response_mode is to use and gets the relevant ResponseModeProvider.
 */
public class DefaultResponseModeProvider extends AbstractResponseModeProvider {

    private static final String RESPONSE_MODE = null;
    private static final String FRAGMENT_RESPONSE_MODE = OAuthConstants.ResponseModes.FRAGMENT;
    private static final String QUERY_RESPONSE_MODE = OAuthConstants.ResponseModes.QUERY;

    @Override
    public String getResponseMode() {

        return RESPONSE_MODE;
    }

    @Override
    public boolean canHandle(AuthorizationResponseDTO authorizationResponseDTO) {

        return true;
    }

    @Override
    public String getAuthResponseRedirectUrl(AuthorizationResponseDTO authorizationResponseDTO) {

        String responseType = authorizationResponseDTO.getResponseType();
        String responseMode;
        if (responseType == null) {
            responseMode =  QUERY_RESPONSE_MODE;
        } else {
            if (OAuthConstants.ResponseModes.DIRECT.equals(authorizationResponseDTO.getResponseMode())) {
                /*Sending the response back in query mode as the standard mode for API based authentication
                 in order for the proceeding flow to process the response and build actual response.*/
                responseMode = QUERY_RESPONSE_MODE;
            } else if (hasIDTokenOrTokenInResponseType(responseType)) {
                responseMode =  FRAGMENT_RESPONSE_MODE;
            } else {
                responseMode =  QUERY_RESPONSE_MODE;
            }
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
