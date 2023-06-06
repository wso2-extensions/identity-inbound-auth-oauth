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
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.responsemode.provider.AuthorizationResponseDTO;
import org.wso2.carbon.identity.oauth2.responsemode.provider.ResponseModeProvider;
import org.wso2.carbon.identity.oauth2.responsemode.provider.jarm.JarmResponseModeProvider;

import java.util.ArrayList;
import java.util.List;

/**
 * This class is used when response_mode = query.jwt
 * This class should not be used when response_type has token or id_token
 */
public class QueryJwtResponseModeProvider extends JarmResponseModeProvider {

    private static final String RESPONSE_MODE = OAuthConstants.ResponseModes.QUERY_JWT;
    private static final String FRAGMENT_JWT_RESPONSE_MODE = OAuthConstants.ResponseModes.FRAGMENT_JWT;
    private static final Log LOG = LogFactory.getLog(QueryJwtResponseModeProvider.class);

    @Override
    public String getResponseMode() {

        return RESPONSE_MODE;
    }

    @Override
    public boolean canHandle(AuthorizationResponseDTO authorizationResponseDTO) {

        // This ResponseModeProvider cannot handle response types that contain "token" or "ide_token".
        String responseType = authorizationResponseDTO.getResponseType();

        return !hasIDTokenOrTokenInResponseType(responseType) &&
                getResponseMode().equals(authorizationResponseDTO.getResponseMode());
    }

    @Override
    public String getAuthResponseRedirectUrl(AuthorizationResponseDTO authorizationResponseDTO) {

        String responseType = authorizationResponseDTO.getResponseType();
        if (hasIDTokenOrTokenInResponseType(responseType)) {
            /*
                When responseType contains "id_token" or "token" the resulting token is passed back as a URI fragment
                as per the JARM specification:
                https://bitbucket.org/openid/fapi/src/master/oauth-v2-jarm.md
             */

            ResponseModeProvider newResponseModeProvider =
                    OAuth2ServiceComponentHolder.getResponseModeProvider(FRAGMENT_JWT_RESPONSE_MODE);
            return newResponseModeProvider.getAuthResponseRedirectUrl(authorizationResponseDTO);
        }

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
            List<String> queryParams = new ArrayList<>();
            queryParams.add("response" + "=" + jwtToken);
            redirectUrl = FrameworkUtils.appendQueryParamsStringToUrl(redirectUrl,
                    String.join("&", queryParams));
        } catch (OAuthSystemException e) {
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
