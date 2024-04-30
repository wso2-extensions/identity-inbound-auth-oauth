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

package org.wso2.carbon.identity.oauth2.responsemode.provider;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;

import java.util.Arrays;

/**
 * Abstract class for response mode provider classes
 */
public abstract class AbstractResponseModeProvider implements ResponseModeProvider {

    private static final String SPACE_SEPARATOR = " ";

    /**
     * Checks if the given response type contains either "id_token" or "token".
     *
     * @param responseType The response type to check.
     * @return {@code true} if "id_token" or "token" is present in the response type, {@code false} otherwise.
     */
    protected boolean hasIDTokenOrTokenInResponseType(String responseType) {

        return hasResponseType(responseType, OAuthConstants.ID_TOKEN)
                || hasResponseType(responseType, OAuthConstants.TOKEN);
    }

    /**
     * Checks if the given response type contains the specified OAuth response type.
     *
     * @param responseType      The response type to check.
     * @param oauthResponseType The OAuth response type to look for.
     * @return {@code true} if the specified OAuth response type is present in the response type,
     * {@code false} otherwise.
     */
    private boolean hasResponseType(String responseType, String oauthResponseType) {

        if (StringUtils.isNotBlank(responseType)) {
            String[] responseTypes = responseType.split(SPACE_SEPARATOR);
            return Arrays.asList(responseTypes).contains(oauthResponseType);
        }
        return false;
    }

    /**
     * Checks whether the relevant ResponseModeProvider can handle the response mode
     * @param authorizationResponseDTO Authorization Response DTO with response mode
     * @return true if response mode can be handled
     */
    @Override
    public boolean canHandle(AuthorizationResponseDTO authorizationResponseDTO) {

        return getResponseMode().equals(authorizationResponseDTO.getResponseMode());
    }
}
