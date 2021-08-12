/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth2.device.response;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.authz.handlers.AbstractResponseTypeHandler;
import org.wso2.carbon.identity.oauth2.device.constants.Constants;
import org.wso2.carbon.identity.oauth2.device.dao.DeviceFlowPersistenceFactory;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeRespDTO;

/**
 * Device response type handler.
 */
public class DeviceFlowResponseTypeHandler extends AbstractResponseTypeHandler {

    private static final Log log = LogFactory.getLog(DeviceFlowResponseTypeHandler.class);

    /**
     * This method is used to handle the response type. After authentication process finish this will redirect to the
     * constant page.
     *
     * @param oauthAuthzMsgCtx Authorization message context.
     * @return Response DTO.
     * @throws IdentityOAuth2Exception Error at device response type handler.
     */
    @Override
    public OAuth2AuthorizeRespDTO issue(OAuthAuthzReqMessageContext oauthAuthzMsgCtx) throws IdentityOAuth2Exception {

        OAuth2AuthorizeRespDTO respDTO = new OAuth2AuthorizeRespDTO();
        OAuth2AuthorizeReqDTO authzReqDTO = oauthAuthzMsgCtx.getAuthorizationReqDTO();
        AuthenticatedUser authenticatedUser = authzReqDTO.getUser();
        String userCode = authzReqDTO.getNonce();
        DeviceFlowPersistenceFactory.getInstance().getDeviceFlowDAO().setAuthzUserAndStatus(userCode,
                Constants.AUTHORIZED, authenticatedUser);
        respDTO.setCallbackURI(authzReqDTO.getCallbackUrl());
        return respDTO;
    }

    @Override
    public boolean isAuthorizedClient(OAuthAuthzReqMessageContext authzReqMsgCtx) throws IdentityOAuth2Exception {

        OAuth2AuthorizeReqDTO authzReqDTO = authzReqMsgCtx.getAuthorizationReqDTO();
        String consumerKey = authzReqDTO.getConsumerKey();

        OAuthAppDO oAuthAppDO = (OAuthAppDO) authzReqMsgCtx.getProperty("OAuthAppDO");
        if (StringUtils.isBlank(oAuthAppDO.getGrantTypes())) {
            if (log.isDebugEnabled()) {
                log.debug("Could not find authorized grant types for client id: " + consumerKey);
            }
            return false;
        }
        String responseType = authzReqDTO.getResponseType();
        String grantType = null;
        if (StringUtils.contains(responseType, Constants.RESPONSE_TYPE_DEVICE)) {
            grantType = OAuthConstants.GrantTypes.DEVICE_CODE;
        }

        if (StringUtils.isBlank(grantType)) {
            if (log.isDebugEnabled()) {
                log.debug("Valid grant type not found for client id: " + consumerKey);
            }
            return false;
        }

        if (!oAuthAppDO.getGrantTypes().contains(grantType)) {
            if (log.isDebugEnabled()) {
                //Do not change this log format as these logs use by external applications
                log.debug("Unsupported Grant Type: " + grantType + " for client id: " + consumerKey);
            }
            return false;
        }
        return true;
    }
}
