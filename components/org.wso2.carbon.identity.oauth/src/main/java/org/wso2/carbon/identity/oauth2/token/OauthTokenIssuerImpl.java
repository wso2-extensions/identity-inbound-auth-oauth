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
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.tokenBinding.TokenBinding;
import org.wso2.carbon.identity.oauth2.tokenBinding.TokenBindingContext;
import org.wso2.carbon.identity.oauth2.tokenBinding.TokenBindingHandler;

public class OauthTokenIssuerImpl implements OauthTokenIssuer {

    private OAuthIssuer oAuthIssuerImpl = OAuthServerConfiguration.getInstance()
            .getOAuthTokenGenerator();

    public String accessToken(OAuthTokenReqMessageContext tokReqMsgCtx) throws OAuthSystemException {
        String accessToken = oAuthIssuerImpl.accessToken();
        String boundAccessToken = bindToken(tokReqMsgCtx, OAuthConstants.HTTP_TB_REFERRED_HEADER_NAME, accessToken)
                .getBoundToken();
        return boundAccessToken;
    }

    public String refreshToken(OAuthTokenReqMessageContext tokReqMsgCtx) throws OAuthSystemException {
        String refreshToken = oAuthIssuerImpl.refreshToken();
        String boundRefreshToken = bindToken(tokReqMsgCtx, OAuthConstants.HTTP_TB_PROVIDED_HEADER_NAME, refreshToken)
                .getBoundToken();
        return boundRefreshToken;
    }

    public String authorizationCode(OAuthAuthzReqMessageContext oauthAuthzMsgCtx) throws OAuthSystemException {
        String authorizationCode = oAuthIssuerImpl.authorizationCode();
        String boundAuthorizationCode = bindToken(oauthAuthzMsgCtx, OAuthConstants.HTTP_TB_REFERRED_HEADER_NAME,
                authorizationCode).getBoundToken();
        return boundAuthorizationCode;
    }

    public String accessToken(OAuthAuthzReqMessageContext oauthAuthzMsgCtx) throws OAuthSystemException {
        String accessToken = oAuthIssuerImpl.accessToken();
        String boundAccessToken = bindToken(oauthAuthzMsgCtx, OAuthConstants.HTTP_TB_REFERRED_HEADER_NAME, accessToken)
                .getBoundToken();
        return boundAccessToken;
    }

    public String refreshToken(OAuthAuthzReqMessageContext oauthAuthzMsgCtx) throws OAuthSystemException {
        String refreshToken = oAuthIssuerImpl.refreshToken();
        String boundRefreshToken = bindToken(oauthAuthzMsgCtx, OAuthConstants.HTTP_TB_PROVIDED_HEADER_NAME, refreshToken)
                .getBoundToken();
        return boundRefreshToken;
    }

    private TokenBindingContext bindToken(OAuthTokenReqMessageContext tokReqMsgCtx, String tokenBindingType, String
            normalToken) {
        TokenBindingContext tokenBindingContext = new TokenBindingContext();
        tokenBindingContext.setTokenBindingType(tokenBindingType);
        tokenBindingContext.setTokReqMsgCtx(tokReqMsgCtx);
        tokenBindingContext.setNormalToken(normalToken);
        TokenBinding tokenBinding = new TokenBindingHandler();
        return tokenBinding.doTokenBinding(tokenBindingContext);
    }

    private TokenBindingContext bindToken(OAuthAuthzReqMessageContext oauthAuthzMsgCtx, String tokenBindingType, String
            normalToken) {
        TokenBindingContext tokenBindingContext = new TokenBindingContext();
        tokenBindingContext.setTokenBindingType(tokenBindingType);
        tokenBindingContext.setOauthAuthzMsgCtx(oauthAuthzMsgCtx);
        tokenBindingContext.setNormalToken(normalToken);
        TokenBinding tokenBinding = new TokenBindingHandler();
        return tokenBinding.doTokenBinding(tokenBindingContext);
    }
}
