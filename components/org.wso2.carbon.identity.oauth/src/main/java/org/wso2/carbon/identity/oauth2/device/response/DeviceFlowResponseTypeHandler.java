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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.authz.handlers.AbstractResponseTypeHandler;
import org.wso2.carbon.identity.oauth2.device.constants.Constants;
import org.wso2.carbon.identity.oauth2.device.dao.DeviceFlowPersistenceFactory;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeRespDTO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

/**
 * device response type handler
 */
public class DeviceFlowResponseTypeHandler extends AbstractResponseTypeHandler {

    private static Log log = LogFactory.getLog(DeviceFlowResponseTypeHandler.class);

    private String AppName;
    private String appName;

    public DeviceFlowResponseTypeHandler() {

    }

    public OAuth2AuthorizeRespDTO issue(OAuthAuthzReqMessageContext oauthAuthzMsgCtx) throws IdentityOAuth2Exception {

        OAuth2AuthorizeRespDTO respDTO = new OAuth2AuthorizeRespDTO();
        OAuth2AuthorizeReqDTO authzReqDTO = oauthAuthzMsgCtx.getAuthorizationReqDTO();
        String clientId = authzReqDTO.getConsumerKey();
        String authenticatedUser = authzReqDTO.getUser().getUserName();
        OAuthAppDO oAuthAppDO = null;
        try {
            oAuthAppDO = OAuth2Util.getAppInformationByClientId(clientId);
            appName = oAuthAppDO.getApplicationName();
            setAppName(appName);
        } catch (InvalidOAuthClientException e) {
            throw new IdentityOAuth2Exception("Error when getting app details for client id : " +
                    clientId, e);
        }

        String UserCode = authzReqDTO.getNonce();
        DeviceFlowPersistenceFactory.getInstance().getDeviceFlowDAO().setAuthzUser(UserCode, authenticatedUser);
        DeviceFlowPersistenceFactory.getInstance().getDeviceFlowDAO().setUserAuthenticated(UserCode,
                Constants.AUTHORIZED);
        respDTO.setCallbackURI(IdentityUtil.getServerURL("/authenticationendpoint/device_success.do?app_name=" +
                appName, false, false));

        return respDTO;
    }

    /**
     *
     * @return application name
     */
    public String getAppName() {

        return AppName;
    }

    /**
     *
     * @param appName
     */
    private void setAppName(String appName) {

        AppName = appName;
    }
}

