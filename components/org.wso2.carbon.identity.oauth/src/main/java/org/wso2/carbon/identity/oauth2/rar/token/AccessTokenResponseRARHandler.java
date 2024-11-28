/*
 * Copyright (c) 2024, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth2.rar.token;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.rar.util.AuthorizationDetailsConstants;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.handlers.response.AccessTokenResponseHandler;

import java.util.HashMap;
import java.util.Map;

import static org.wso2.carbon.identity.oauth2.rar.util.AuthorizationDetailsUtils.isRichAuthorizationRequest;

/**
 * Class responsible for modifying the access token response to include user-consented authorization details.
 *
 * <p>This class enhances the access token response by appending user-consented authorization details.
 * It is invoked by the {@link org.wso2.carbon.identity.oauth2.token.AccessTokenIssuer#issue} method during
 * the OAuth 2.0 token issuance process.</p>
 */
public class AccessTokenResponseRARHandler implements AccessTokenResponseHandler {

    private static final Log log = LogFactory.getLog(AccessTokenResponseRARHandler.class);

    /**
     * Returns Rich Authorization Request attributes to be added to the access token response.
     *
     * @param oAuthTokenReqMessageContext {@link OAuthTokenReqMessageContext} token request message context.
     * @return Map of additional attributes to be added to the token response.
     * @throws IdentityOAuth2Exception Error while constructing additional token response attributes.
     */
    @Override
    public Map<String, Object> getAdditionalTokenResponseAttributes(
            final OAuthTokenReqMessageContext oAuthTokenReqMessageContext) throws IdentityOAuth2Exception {

        Map<String, Object> additionalAttributes = new HashMap<>();
        if (isRichAuthorizationRequest(oAuthTokenReqMessageContext.getAuthorizationDetails())) {

            if (log.isDebugEnabled()) {
                log.debug("Adding authorization details into the token response: " + oAuthTokenReqMessageContext
                        .getAuthorizationDetails().toReadableText());
            }
            additionalAttributes.put(AuthorizationDetailsConstants.AUTHORIZATION_DETAILS,
                    oAuthTokenReqMessageContext.getAuthorizationDetails().toSet());
        }
        return additionalAttributes;
    }
}
