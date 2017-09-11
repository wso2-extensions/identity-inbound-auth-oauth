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
import org.wso2.carbon.identity.oauth2.model.HttpRequestHeader;

public class OauthTokenIssuerImpl implements OauthTokenIssuer {


    private OAuthIssuer oAuthIssuerImpl = OAuthServerConfiguration.getInstance()
            .getOAuthTokenGenerator();

    public String accessToken(OAuthTokenReqMessageContext tokReqMsgCtx) throws OAuthSystemException {
        String tokenBindingId = checkTB(tokReqMsgCtx,OAuthConstants.HTTP_TB_REFERRED_HEADER_NAME);
        if (!tokenBindingId.isEmpty()){
            return tokenBindingId;
        }
        return oAuthIssuerImpl.accessToken();
    }

    public String refreshToken(OAuthTokenReqMessageContext tokReqMsgCtx) throws OAuthSystemException {
        String tokenBindingId = checkTB(tokReqMsgCtx,OAuthConstants.HTTP_TB_PROVIDED_HEADER_NAME);
        if (!tokenBindingId.isEmpty()){
            return tokenBindingId;
        }
        return oAuthIssuerImpl.refreshToken();
    }

    public String authorizationCode(OAuthAuthzReqMessageContext oauthAuthzMsgCtx) throws OAuthSystemException {
        String tokenBindingId = checkTB(oauthAuthzMsgCtx,OAuthConstants.HTTP_TB_REFERRED_HEADER_NAME);
        if (!tokenBindingId.isEmpty()){
            return tokenBindingId;
        }
        return oAuthIssuerImpl.authorizationCode();
    }

    public String accessToken(OAuthAuthzReqMessageContext oauthAuthzMsgCtx) throws OAuthSystemException {
        String tokenBindingId = checkTB(oauthAuthzMsgCtx, OAuthConstants.HTTP_TB_REFERRED_HEADER_NAME);
        if (!tokenBindingId.isEmpty()){
            return tokenBindingId;
        }
        return oAuthIssuerImpl.accessToken();
    }

    public String refreshToken(OAuthAuthzReqMessageContext oauthAuthzMsgCtx) throws OAuthSystemException {
        String tokenBindingId = checkTB(oauthAuthzMsgCtx,OAuthConstants.HTTP_TB_PROVIDED_HEADER_NAME);
        if (!tokenBindingId.isEmpty()){
            return tokenBindingId;
        }
        return oAuthIssuerImpl.refreshToken();
    }
    //check for token binding header in the request
    private String checkTB(OAuthTokenReqMessageContext tokReqMsgCtx,String httpTBheader) {
        HttpRequestHeader[] httpRequestHeaders = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getHttpRequestHeaders();
        String tokenBindingId = "";
        if (httpRequestHeaders != null) {
            for (HttpRequestHeader httpRequestHeader : httpRequestHeaders) {
                if (httpRequestHeader.getName().equals(httpTBheader)) {
                    tokenBindingId = httpRequestHeader.getValue()[0];
                    break;
                }
            }

        }
        return tokenBindingId;
    }

    private String checkTB(OAuthAuthzReqMessageContext oauthAuthzMsgCtx,String httpTBheader) {
        HttpRequestHeader[] httpRequestHeaders = oauthAuthzMsgCtx.getAuthorizationReqDTO().getHttpRequestHeaders();
        String tokenBindingId = "";
        if (httpRequestHeaders != null) {
            for (HttpRequestHeader httpRequestHeader : httpRequestHeaders) {
                if (httpRequestHeader.getName().equals(httpTBheader)) {
                    tokenBindingId = httpRequestHeader.getValue()[0];
                    break;
                }
            }

        }
        return tokenBindingId;
    }

}
