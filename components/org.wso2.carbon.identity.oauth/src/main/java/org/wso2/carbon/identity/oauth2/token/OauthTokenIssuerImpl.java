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
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;

public class OauthTokenIssuerImpl implements OauthTokenIssuer {

    private OAuthIssuer oAuthIssuerImpl = OAuthServerConfiguration.getInstance()
            .getOAuthTokenGenerator();
    private boolean persistAccessTokenAlias = true;

    public String accessToken(OAuthTokenReqMessageContext tokReqMsgCtx) throws OAuthSystemException {
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
