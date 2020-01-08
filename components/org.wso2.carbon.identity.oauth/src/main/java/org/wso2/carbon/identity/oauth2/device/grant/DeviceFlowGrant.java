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

package org.wso2.carbon.identity.oauth2.device.grant;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.device.constants.Constants;
import org.wso2.carbon.identity.oauth2.device.dao.DeviceFlowPersistenceFactory;
import org.wso2.carbon.identity.oauth2.device.errorcodes.DeviceErrorCodes;
import org.wso2.carbon.identity.oauth2.device.model.DeviceFlowDO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenRespDTO;
import org.wso2.carbon.identity.oauth2.model.RequestParameter;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.AbstractAuthorizationGrantHandler;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.sql.Timestamp;
import java.util.Date;

/**
 * Device flow grant type for Identity Server.
 */
public class DeviceFlowGrant extends AbstractAuthorizationGrantHandler {

    private static Log log = LogFactory.getLog(DeviceFlowGrant.class);

    @Override
    public boolean validateGrant(OAuthTokenReqMessageContext oAuthTokenReqMessageContext) throws
            IdentityOAuth2Exception {

        super.validateGrant(oAuthTokenReqMessageContext);
        boolean authStatus = false;
        RequestParameter[] parameters = oAuthTokenReqMessageContext.getOauth2AccessTokenReqDTO()
                .getRequestParameters();
        String deviceCode = null;
        String deviceStatus;

        for (RequestParameter parameter : parameters) {
            if (Constants.DEVICE_CODE.equals(parameter.getKey()) && parameter.getValue() != null
                    && parameter.getValue().length > 0) {
                deviceCode = parameter.getValue()[0];
                break;
            }
        }

        if (log.isDebugEnabled()) {
            log.debug("Getting ready to release token for device_code: " + deviceCode);
        }

        if (deviceCode != null) {
            DeviceFlowDO deviceFlowDO = DeviceFlowPersistenceFactory.getInstance().getDeviceFlowDAO()
                    .getAuthenticationDetails(deviceCode);
            Date date = new Date();
            deviceStatus = deviceFlowDO.getStatus();
            deviceFlowDO.setScope(getScopes(deviceCode));
            deviceFlowDO.setDeviceCode(deviceCode);
            if (Constants.NOT_EXIST.equals(deviceStatus)) {
                throw new IdentityOAuth2Exception(DeviceErrorCodes.INVALID_REQUEST);
            } else if (Constants.EXPIRED.equals(deviceStatus) || isExpiredDeviceCode(deviceFlowDO, date)) {
                throw new IdentityOAuth2Exception(DeviceErrorCodes.SubDeviceErrorCodes.EXPIRED_TOKEN);
            } else if (Constants.AUTHORIZED.equals(deviceStatus)) {
                authStatus = true;
                DeviceFlowPersistenceFactory.getInstance().getDeviceFlowDAO().setDeviceCodeExpired(deviceCode,
                        Constants.EXPIRED);
                this.setPropertiesForTokenGeneration(oAuthTokenReqMessageContext, deviceFlowDO);
            } else if (Constants.USED.equals(deviceStatus) || Constants.PENDING.equals(deviceStatus)) {
                Timestamp newPollTime = new Timestamp(date.getTime());
                if (isValidPollTime(newPollTime, deviceFlowDO)) {
                    DeviceFlowPersistenceFactory.getInstance().getDeviceFlowDAO()
                            .setLastPollTime(deviceCode, newPollTime);
                    throw new IdentityOAuth2Exception(DeviceErrorCodes.SubDeviceErrorCodes.AUTHORIZATION_PENDING);
                } else {
                    DeviceFlowPersistenceFactory.getInstance().getDeviceFlowDAO()
                            .setLastPollTime(deviceCode, newPollTime);
                    throw new IdentityOAuth2Exception(DeviceErrorCodes.SubDeviceErrorCodes.SLOW_DOWN);
                }
            }
        }
        return authStatus;
    }

    /**
     * To set the properties of the token generation.
     *
     * @param tokReqMsgCtx Token request message context.
     * @param deviceFlowDO Device flow DO set.
     */
    private void setPropertiesForTokenGeneration(OAuthTokenReqMessageContext tokReqMsgCtx, DeviceFlowDO deviceFlowDO) {

        AuthenticatedUser authzUser = deviceFlowDO.getAuthorizedUser();
        String[] scopeSet = OAuth2Util.buildScopeArray(deviceFlowDO.getScope());
        tokReqMsgCtx.setAuthorizedUser(authzUser);
        if (StringUtils.isNotBlank(deviceFlowDO.getScope())) {
            tokReqMsgCtx.setScope(scopeSet);
        } else {
            tokReqMsgCtx.setScope(tokReqMsgCtx.getOauth2AccessTokenReqDTO().getScope());
        }
    }

    @Override
    public OAuth2AccessTokenRespDTO issue(OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception {

        return super.issue(tokReqMsgCtx);
    }

    /**
     * This method use to check whether device code is expired or not.
     *
     * @param deviceFlowDO DO set that contains values from database.
     * @param date         Time that request has came.
     * @return true or false.
     */
    private static boolean isExpiredDeviceCode(DeviceFlowDO deviceFlowDO, Date date) throws IdentityOAuth2Exception {

        if (deviceFlowDO.getExpiryTime().getTime() < date.getTime()) {
            DeviceFlowPersistenceFactory.getInstance().getDeviceFlowDAO().
                    setDeviceCodeExpired(deviceFlowDO.getDeviceCode(), Constants.EXPIRED);
            return true;
        } else {
            return false;
        }
    }

    /**
     * This checks whether polling frequency is correct or not.
     *
     * @param newPollTime  Time of the new poll request.
     * @param deviceFlowDO DO class that contains values from database.
     * @return true or false.
     */
    private static boolean isValidPollTime(Timestamp newPollTime, DeviceFlowDO deviceFlowDO) {

        return newPollTime.getTime() - deviceFlowDO.getLastPollTime().getTime() > deviceFlowDO.getPollTime();
    }

    /**
     * Get scopes for device code.
     *
     * @param deviceCode Code that is used to identify the device.
     * @return scopes
     * @throws IdentityOAuth2Exception Error while getting scopes for device code.
     */
    private String getScopes(String deviceCode) throws IdentityOAuth2Exception {

        return String.join(Constants.SEPARATED_WITH_SPACE,
                DeviceFlowPersistenceFactory.getInstance().getDeviceFlowDAO().getScopesForDeviceCode(deviceCode));
    }
}
