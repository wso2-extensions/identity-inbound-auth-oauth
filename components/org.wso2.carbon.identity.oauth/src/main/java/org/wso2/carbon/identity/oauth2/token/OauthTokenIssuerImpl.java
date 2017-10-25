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
import org.wso2.carbon.identity.oauth2.model.HttpRequestHeader;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

public class OauthTokenIssuerImpl implements OauthTokenIssuer {


    private OAuthIssuer oAuthIssuerImpl = OAuthServerConfiguration.getInstance()
            .getOAuthTokenGenerator();

    public String accessToken(OAuthTokenReqMessageContext tokReqMsgCtx) throws OAuthSystemException {
        String tokenBindingId = OAuth2Util.checkTB(tokReqMsgCtx,OAuthConstants.HTTP_TB_REFERRED_HEADER_NAME);
        String accesstoken=oAuthIssuerImpl.accessToken();
        if (!tokenBindingId.isEmpty()){
            accesstoken=OAuth2Util.hashTB(tokenBindingId)+";"+accesstoken;
            accesstoken=baseencodeTB(accesstoken);
        }
        return accesstoken ;
    }

    public String refreshToken(OAuthTokenReqMessageContext tokReqMsgCtx) throws OAuthSystemException {
        String tokenBindingId = OAuth2Util.checkTB(tokReqMsgCtx,OAuthConstants.HTTP_TB_PROVIDED_HEADER_NAME);
        String refreshtoken=oAuthIssuerImpl.refreshToken();
        if (!tokenBindingId.isEmpty()){
            refreshtoken=OAuth2Util.hashTB(tokenBindingId)+":"+refreshtoken;
            refreshtoken=baseencodeTB(refreshtoken);
        }
        return refreshtoken;
    }

    public String authorizationCode(OAuthAuthzReqMessageContext oauthAuthzMsgCtx) throws OAuthSystemException {
        String tokenBindingId = OAuth2Util.checkTB(oauthAuthzMsgCtx,OAuthConstants.HTTP_TB_REFERRED_HEADER_NAME);
        String authorizationcode=oAuthIssuerImpl.authorizationCode();
        if (!tokenBindingId.isEmpty()){
            authorizationcode=OAuth2Util.hashTB(tokenBindingId)+";"+authorizationcode;
            authorizationcode=baseencodeTB(authorizationcode);
        }
        return authorizationcode;
    }

    public String accessToken(OAuthAuthzReqMessageContext oauthAuthzMsgCtx) throws OAuthSystemException {
        String tokenBindingId = OAuth2Util.checkTB(oauthAuthzMsgCtx, OAuthConstants.HTTP_TB_REFERRED_HEADER_NAME);
        String accesstoken=oAuthIssuerImpl.accessToken();
        if (!tokenBindingId.isEmpty()){
            accesstoken=OAuth2Util.hashTB(tokenBindingId)+";"+accesstoken;
            accesstoken=baseencodeTB(accesstoken);
        }
        return accesstoken ;
    }

    public String refreshToken(OAuthAuthzReqMessageContext oauthAuthzMsgCtx) throws OAuthSystemException {
        String tokenBindingId = OAuth2Util.checkTB(oauthAuthzMsgCtx,OAuthConstants.HTTP_TB_PROVIDED_HEADER_NAME);
        String refreshtoken=oAuthIssuerImpl.refreshToken();
        if (!tokenBindingId.isEmpty()){
            refreshtoken=OAuth2Util.hashTB(tokenBindingId)+":"+refreshtoken;
            refreshtoken=baseencodeTB(refreshtoken);
        }
        return refreshtoken;
    }
    public String baseencodeTB(String token){
        token = Base64Utils.encode(token.getBytes(Charsets.UTF_8));
        return token;
    }


}
