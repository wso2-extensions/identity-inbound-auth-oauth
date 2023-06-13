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

import com.nimbusds.jwt.JWTClaimsSet;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth2.responsemode.provider.AuthorizationResponseDTO;
import org.wso2.carbon.identity.oauth2.responsemode.provider.jarm.JarmResponseModeProvider;

/**
 * This class is used when response_mode = fragment.jwt
 */
public class FragmentJwtResponseModeProvider extends JarmResponseModeProvider {

    private static final String RESPONSE_MODE = OAuthConstants.ResponseModes.FRAGMENT_JWT;
    private static final Log LOG = LogFactory.getLog(FragmentJwtResponseModeProvider.class);

    @Override
    public String getResponseMode() {

        return RESPONSE_MODE;
    }

    @Override
    public String getAuthResponseRedirectUrl(AuthorizationResponseDTO authorizationResponseDTO) {

        String redirectUrl = authorizationResponseDTO.getRedirectUrl();
        JWTClaimsSet jwtClaimsSet;
        String jwtToken;

        try {
            if (authorizationResponseDTO.isError()) {
                jwtClaimsSet = getErrorJWTClaimsSet(authorizationResponseDTO);
            } else {
                jwtClaimsSet = getJWTClaimsSet(authorizationResponseDTO);
            }
            jwtToken = getJWTToken(authorizationResponseDTO, jwtClaimsSet);
            redirectUrl += "#response=" + jwtToken;

        } catch (Exception e) {
            LOG.error("Error occurred when getting JWT token ", e);
            redirectUrl += "#error=" + authorizationResponseDTO.getErrorResponseDTO().getError() +
                    "&error_description=" +
                    authorizationResponseDTO
                            .getErrorResponseDTO()
                            .getErrorDescription().replace(" ", "+");
        }
        authorizationResponseDTO.setRedirectUrl(redirectUrl);
        return redirectUrl;
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
