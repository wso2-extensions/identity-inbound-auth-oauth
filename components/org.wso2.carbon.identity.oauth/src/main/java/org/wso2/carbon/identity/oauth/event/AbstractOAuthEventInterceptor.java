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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.event;

import org.wso2.carbon.identity.core.handler.AbstractIdentityHandler;
import org.wso2.carbon.identity.core.model.IdentityEventListenerConfig;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenRespDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeRespDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2IntrospectionResponseDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationRequestDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationResponseDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuthRevocationRequestDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuthRevocationResponseDTO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.RefreshTokenValidationDataDO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;

import java.util.Map;

/**
 * Oauth Event Interceptor implemented for publishing oauth data to DAS
 */
public class AbstractOAuthEventInterceptor extends AbstractIdentityHandler implements OAuthEventInterceptor {


    @Override
    public void onPreTokenIssue(OAuth2AccessTokenReqDTO tokenReqDTO, OAuthTokenReqMessageContext tokReqMsgCtx,
                                Map<String, Object> params) throws IdentityOAuth2Exception {
        // Nothing to implement
    }

    @Override
    public void onPostTokenIssue(OAuth2AccessTokenReqDTO tokenReqDTO, OAuth2AccessTokenRespDTO tokenRespDTO,
                                 OAuthTokenReqMessageContext tokReqMsgCtx, Map<String, Object> params) throws
            IdentityOAuth2Exception {
        // Nothing to implement
    }

    @Override
    public void onPreTokenIssue(OAuthAuthzReqMessageContext oauthAuthzMsgCtx, Map<String, Object> params) throws
            IdentityOAuth2Exception {
        // Nothing to implement
    }

    @Override
    public void onPostTokenIssue(OAuthAuthzReqMessageContext oauthAuthzMsgCtx, AccessTokenDO tokenDO,
                                 OAuth2AuthorizeRespDTO respDTO, Map<String, Object> params)
            throws IdentityOAuth2Exception {
        // Nothing to implement
    }

    @Override
    public void onPreTokenRenewal(OAuth2AccessTokenReqDTO tokenReqDTO, OAuthTokenReqMessageContext tokReqMsgCtx,
                                  Map<String, Object> params) throws IdentityOAuth2Exception {
        // Nothing to implement
    }

    @Override
    public void onPostTokenRenewal(OAuth2AccessTokenReqDTO tokenReqDTO, OAuth2AccessTokenRespDTO tokenRespDTO,
                                   OAuthTokenReqMessageContext tokReqMsgCtx, Map<String, Object> params) throws
            IdentityOAuth2Exception {
        // Nothing to implement
    }

    @Override
    public void onPreTokenRevocationByClient(OAuthRevocationRequestDTO revokeRequestDTO, Map<String, Object> params)
            throws IdentityOAuth2Exception {
        // Nothing to implement

    }

    @Override
    public void onPostTokenRevocationByClient(OAuthRevocationRequestDTO revokeRequestDTO,
                                              OAuthRevocationResponseDTO revokeResponseDTO, AccessTokenDO accessTokenDO,
                                              RefreshTokenValidationDataDO refreshTokenDO, Map<String, Object> params)
            throws IdentityOAuth2Exception {
        // Nothing to implement
    }

    @Override
    public void onPreTokenRevocationByResourceOwner(
            org.wso2.carbon.identity.oauth.dto.OAuthRevocationRequestDTO revokeRequestDTO, Map<String, Object> params)
            throws IdentityOAuth2Exception {
        // Nothing to implement

    }

    @Override
    public void onPostTokenRevocationByResourceOwner(
            org.wso2.carbon.identity.oauth.dto.OAuthRevocationRequestDTO revokeRequestDTO,
            org.wso2.carbon.identity.oauth.dto.OAuthRevocationResponseDTO revokeRespDTO,
            AccessTokenDO accessTokenDO, Map<String, Object> params) throws IdentityOAuth2Exception {
        // Nothing to implement
    }

    @Override
    public void onPreTokenValidation(OAuth2TokenValidationRequestDTO validationReqDTO, Map<String, Object> params)
            throws IdentityOAuth2Exception {
        // Nothing to implement
    }

    @Override
    public void onPostTokenValidation(OAuth2TokenValidationRequestDTO validationReqDTO,
                                      OAuth2TokenValidationResponseDTO validationResponseDTO, Map<String, Object>
                                              params) throws IdentityOAuth2Exception {
        // Nothing to implement

    }

    @Override
    public void onPostTokenValidation(OAuth2TokenValidationRequestDTO oAuth2TokenValidationRequestDTO,
                                      OAuth2IntrospectionResponseDTO oAuth2IntrospectionResponseDTO, Map<String,
            Object> params) throws IdentityOAuth2Exception {
        // Nothing to implement

    }

    public boolean isEnabled() {
        IdentityEventListenerConfig identityEventListenerConfig = IdentityUtil.readEventListenerProperty
                (AbstractIdentityHandler.class.getName(), this.getClass().getName());
        return identityEventListenerConfig == null ? false : Boolean.parseBoolean(identityEventListenerConfig
                .getEnable());
    }

}
