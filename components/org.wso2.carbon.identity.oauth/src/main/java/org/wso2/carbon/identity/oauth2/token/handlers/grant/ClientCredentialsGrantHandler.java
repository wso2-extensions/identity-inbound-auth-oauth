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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.token.handlers.grant;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;

/**
 * Grant Handler for Grant Type : client_credentials
 */
public class ClientCredentialsGrantHandler extends AbstractAuthorizationGrantHandler {

    private static final Log log = LogFactory.getLog(ClientCredentialsGrantHandler.class);

    @Override
    public boolean validateGrant(OAuthTokenReqMessageContext tokReqMsgCtx)
            throws IdentityOAuth2Exception {

        super.validateGrant(tokReqMsgCtx);
        // By this time, we have already validated client credentials.
        tokReqMsgCtx.setScope(tokReqMsgCtx.getOauth2AccessTokenReqDTO().getScope());
        return true;
    }

    @Override
    public boolean isOfTypeApplicationUser() throws IdentityOAuth2Exception {
        return false;
    }

    @Override
    public boolean issueRefreshToken() throws IdentityOAuth2Exception {

        return OAuthServerConfiguration.getInstance()
                .getValueForIsRefreshTokenAllowed(OAuthConstants.GrantTypes.CLIENT_CREDENTIALS);
    }

    public boolean checkIfApplicationEnabled(OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception {

        OAuth2AccessTokenReqDTO tokenReq = tokReqMsgCtx.getOauth2AccessTokenReqDTO();
        ServiceProvider serviceProvider = getServiceProvider(tokenReq);
        return serviceProvider.isApplicationAccessEnabled();
    }

    private ServiceProvider getServiceProvider(OAuth2AccessTokenReqDTO tokenReq) throws IdentityOAuth2Exception {

        ServiceProvider serviceProvider;
        try {
            serviceProvider = OAuth2ServiceComponentHolder.getApplicationMgtService().getServiceProviderByClientId(
                    tokenReq.getClientId(), OAuthConstants.Scope.OAUTH2, tokenReq.getTenantDomain());
        } catch (IdentityApplicationManagementException e) {
            throw new IdentityOAuth2Exception("Error occurred while retrieving OAuth2 application data for client id " +
                    tokenReq.getClientId(), e);
        }
        if (serviceProvider == null) {
            if (log.isDebugEnabled()) {
                log.debug("Could not find an application for client id: " + tokenReq.getClientId()
                        + ", scope: " + OAuthConstants.Scope.OAUTH2 + ", tenant: " + tokenReq.getTenantDomain());
            }
            throw new IdentityOAuth2Exception("Service Provider not found");
        }
        return serviceProvider;
    }
}
