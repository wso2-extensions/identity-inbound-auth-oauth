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

import org.apache.axiom.util.base64.Base64Utils;
import org.apache.commons.io.Charsets;
import org.apache.oltu.oauth2.as.issuer.OAuthIssuer;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.utils.xml.StringUtils;

public class OauthTokenIssuerImpl implements OauthTokenIssuer {


    private OAuthIssuer oAuthIssuerImpl = OAuthServerConfiguration.getInstance()
            .getOAuthTokenGenerator();

    public String accessToken(OAuthTokenReqMessageContext tokReqMsgCtx) throws OAuthSystemException {
        String tokenBindingId = OAuth2Util.findTokenBindingHeader(tokReqMsgCtx,
                OAuthConstants.HTTP_TB_REFERRED_HEADER_NAME);
        String accessToken = oAuthIssuerImpl.accessToken();
        return bindToken(tokenBindingId, accessToken, ";");
    }

    public String refreshToken(OAuthTokenReqMessageContext tokReqMsgCtx) throws OAuthSystemException {
        String tokenBindingId = OAuth2Util.findTokenBindingHeader(tokReqMsgCtx,
                OAuthConstants.HTTP_TB_PROVIDED_HEADER_NAME);
        String refreshToken = oAuthIssuerImpl.refreshToken();
        return bindToken(tokenBindingId, refreshToken, ";");
    }

    public String authorizationCode(OAuthAuthzReqMessageContext oauthAuthzMsgCtx) throws OAuthSystemException {
        String tokenBindingId = OAuth2Util.findTokenBindingHeader(oauthAuthzMsgCtx,
                OAuthConstants.HTTP_TB_REFERRED_HEADER_NAME);
        String authorizationCode = oAuthIssuerImpl.authorizationCode();
        return bindToken(tokenBindingId, authorizationCode, ";");
    }

    public String accessToken(OAuthAuthzReqMessageContext oauthAuthzMsgCtx) throws OAuthSystemException {
        String tokenBindingId = OAuth2Util.findTokenBindingHeader(oauthAuthzMsgCtx,
                OAuthConstants.HTTP_TB_REFERRED_HEADER_NAME);
        String accessToken = oAuthIssuerImpl.accessToken();
        return bindToken(tokenBindingId, accessToken, ";");
    }

    public String refreshToken(OAuthAuthzReqMessageContext oauthAuthzMsgCtx) throws OAuthSystemException {
        String tokenBindingId = OAuth2Util.findTokenBindingHeader(oauthAuthzMsgCtx,
                OAuthConstants.HTTP_TB_PROVIDED_HEADER_NAME);
        String refreshToken = oAuthIssuerImpl.refreshToken();
        return bindToken(tokenBindingId, refreshToken, ":");
    }

    private String bindToken(String tokenBindingID, String token, String delimiter) {
        if (!StringUtils.isEmpty(tokenBindingID)) {
            String newToken = OAuth2Util.hashOfString(tokenBindingID) + delimiter + token;
            String encodedToken = base64Encode(newToken);
            return encodedToken;
        }
        return token;
    }

    private String base64Encode(String token) {
        token = Base64Utils.encode(token.getBytes(Charsets.UTF_8));
        return token;
    }

}
