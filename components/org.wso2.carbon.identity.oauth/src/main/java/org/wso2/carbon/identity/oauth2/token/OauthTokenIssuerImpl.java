/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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


package org.wso2.carbon.identity.oauth2.token;

import org.apache.oltu.oauth2.as.issuer.OAuthIssuer;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.token.bindings.TokenBinding;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.registry.core.utils.UUIDGenerator;

import static org.wso2.carbon.identity.oauth.common
        .OAuthConstants.RENEW_TOKEN_WITHOUT_REVOKING_EXISTING_ENABLE_CONFIG_FOR_OPAQUE;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.REQUEST_BINDING_TYPE;

/**
 * UUID based access token issuer builder.
 */
public class OauthTokenIssuerImpl implements OauthTokenIssuer {

    private OAuthIssuer oAuthIssuerImpl = OAuthServerConfiguration.getInstance()
            .getOAuthTokenGenerator();
    private boolean persistAccessTokenAlias = true;

    public String accessToken(OAuthTokenReqMessageContext tokReqMsgCtx) throws OAuthSystemException {
        boolean renewWithoutRevokingExistingEnabled = Boolean.parseBoolean(
                IdentityUtil.getProperty(RENEW_TOKEN_WITHOUT_REVOKING_EXISTING_ENABLE_CONFIG_FOR_OPAQUE));

        if (renewWithoutRevokingExistingEnabled && tokReqMsgCtx != null && tokReqMsgCtx.getTokenBinding() == null
                && (OAuth2ServiceComponentHolder.getOpaqueRenewWithoutRevokeAllowedGrantTypes()
                .contains(tokReqMsgCtx.getOauth2AccessTokenReqDTO().getGrantType()))) {
            String tokenBindingValue = UUIDGenerator.generateUUID();
            tokReqMsgCtx.setTokenBinding(
                    new TokenBinding(REQUEST_BINDING_TYPE, OAuth2Util.getTokenBindingReference(tokenBindingValue),
                            tokenBindingValue));
        }
        return oAuthIssuerImpl.accessToken();
    }

    public String refreshToken(OAuthTokenReqMessageContext tokReqMsgCtx) throws OAuthSystemException {
        return oAuthIssuerImpl.refreshToken();
    }

    public String authorizationCode(OAuthAuthzReqMessageContext oauthAuthzMsgCtx) throws OAuthSystemException {
        return oAuthIssuerImpl.authorizationCode();
    }

    public String accessToken(OAuthAuthzReqMessageContext oauthAuthzMsgCtx) throws OAuthSystemException {
        return oAuthIssuerImpl.accessToken();
    }

    public String refreshToken(OAuthAuthzReqMessageContext oauthAuthzMsgCtx) throws OAuthSystemException {
        return oAuthIssuerImpl.refreshToken();
    }

    public void setPersistAccessTokenAlias(boolean persistAccessTokenAlias) {
        this.persistAccessTokenAlias = persistAccessTokenAlias;
    }

    public boolean usePersistedAccessTokenAlias() {
        return persistAccessTokenAlias;
    }
}
