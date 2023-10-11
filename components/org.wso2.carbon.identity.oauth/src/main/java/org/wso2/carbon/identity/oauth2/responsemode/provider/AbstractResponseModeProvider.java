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
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;

/**
 * Abstract class for response mode provider classes
 */
public abstract class AbstractResponseModeProvider implements ResponseModeProvider {

    /**
     * Check whether the response type is "token" or "id_token"
     * @param responseType response_type passed
     * @return true if response_type is "token" or "id_token"
     */
    protected boolean hasIDTokenOrTokenInResponseType(String responseType) {

        return StringUtils.isNotBlank(responseType)
                && (responseType.toLowerCase().contains(OAuthConstants.ID_TOKEN)
                || responseType.toLowerCase().contains(OAuthConstants.TOKEN));
    }

    /**
     * Checks whether the relevant ResponseModeProvider can handle the response mode
     * @param authorizationResponseDTO Authorization Response DTO with response mode
     * @return true if response mode can be handled
     */
    @Override
    public boolean canHandle(AuthorizationResponseDTO authorizationResponseDTO) throws OAuthProblemException {

        return getResponseMode().equals(authorizationResponseDTO.getResponseMode());
    }
}
