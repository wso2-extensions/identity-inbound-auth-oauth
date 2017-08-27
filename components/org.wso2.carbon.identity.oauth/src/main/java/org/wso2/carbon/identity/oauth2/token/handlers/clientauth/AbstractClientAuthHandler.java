/*
 * Copyright (c) 2015, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth2.token.handlers.clientauth;

import org.apache.axis2.util.JavaUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;

import java.util.Properties;

public abstract class AbstractClientAuthHandler implements ClientAuthenticationHandler {

    protected Properties properties;
    protected String authConfig;
    private static Log log = LogFactory.getLog(AbstractClientAuthHandler.class);

    @Override
    public void init(Properties properties) throws IdentityOAuth2Exception {
        this.properties = properties;
    }

    @Override
    public boolean canAuthenticate(OAuthTokenReqMessageContext tokReqMsgCtx)
            throws IdentityOAuth2Exception {

        OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO = tokReqMsgCtx.getOauth2AccessTokenReqDTO();

        if (StringUtils.isNotEmpty(oAuth2AccessTokenReqDTO.getClientId()) &&
                StringUtils.isNotEmpty(oAuth2AccessTokenReqDTO.getClientSecret())) {
            if (log.isDebugEnabled()) {
                log.debug("Can authenticate with client ID and Secret." +
                        " Client ID: "+ oAuth2AccessTokenReqDTO.getClientId());
            }
            return true;

        } else {
            if (org.wso2.carbon.identity.oauth.common.GrantType.SAML20_BEARER.toString().equals(
                    oAuth2AccessTokenReqDTO.getGrantType())) {

                //Getting configured value for client credential validation requirements
                authConfig = properties.getProperty(
                        OAuthConstants.CLIENT_AUTH_CREDENTIAL_VALIDATION);

                if (log.isDebugEnabled()) {
                    log.debug("Grant type : " + oAuth2AccessTokenReqDTO.getGrantType());
                }

                //If user has set strict validation to false, can authenticate without credentials
                if (StringUtils.isNotEmpty(authConfig) && JavaUtils.isFalseExplicitly(authConfig)) {
                    if (log.isDebugEnabled()) {
                        log.debug("Client auth credential validation set to : " + authConfig + ". Can authenticate " +
                                "without client secret");
                    }
                    return true;
                }
            }
        }
        return false;
    }

    @Override
    public boolean authenticateClient(OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception {

        OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO = tokReqMsgCtx.getOauth2AccessTokenReqDTO();

        //Skipping credential validation for saml2 bearer if not configured as needed
        if (StringUtils.isEmpty(oAuth2AccessTokenReqDTO.getClientSecret()) && org.wso2.carbon.identity.oauth.common
                .GrantType.SAML20_BEARER.toString().equals(oAuth2AccessTokenReqDTO.getGrantType()) && JavaUtils
                .isFalseExplicitly(authConfig)) {
            if (log.isDebugEnabled()) {
                log.debug("Grant type : " + oAuth2AccessTokenReqDTO.getGrantType() + " Strict client validation set " +
                        "to : " + authConfig + " Authenticating without client secret");
            }
            return true;
        }

        if (log.isDebugEnabled()) {
            log.debug("Grant type : " + oAuth2AccessTokenReqDTO.getGrantType() + " " +
                    "Strict client validation set to : " + authConfig);
        }
        return false;
    }
}
