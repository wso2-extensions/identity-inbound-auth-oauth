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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.device.constants.Constants;
import org.wso2.carbon.identity.oauth2.device.dao.DeviceFlowPersistenceFactory;
import org.wso2.carbon.identity.oauth2.device.errorcodes.DeviceErrorCodes;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenRespDTO;
import org.wso2.carbon.identity.oauth2.model.RequestParameter;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.AbstractAuthorizationGrantHandler;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.sql.Timestamp;
import java.util.Date;
import java.util.HashMap;

/**
 * Device flow grant type for Identity Server.
 */
public class DeviceFlowGrant extends AbstractAuthorizationGrantHandler {

    private static Log log = LogFactory.getLog(DeviceFlowGrant.class);

    @Override
    public boolean validateGrant(OAuthTokenReqMessageContext oAuthTokenReqMessageContext) throws
            IdentityOAuth2Exception {

        super.validateGrant(oAuthTokenReqMessageContext);
        OAuth2AccessTokenReqDTO tokenReq = oAuthTokenReqMessageContext.getOauth2AccessTokenReqDTO();

        boolean authStatus = false;

        // extract request parameters
        RequestParameter[] parameters = oAuthTokenReqMessageContext.getOauth2AccessTokenReqDTO().getRequestParameters();

        String DeviceCode = null;
        String deviceStatus = null;
        HashMap results = new HashMap<>();

        // find out device_code
        for (RequestParameter parameter : parameters) {
            if (Constants.DEVICE_CODE.equals(parameter.getKey())) {
                if (parameter.getValue() != null && parameter.getValue().length > 0) {
                    DeviceCode = parameter.getValue()[0];
                }
            }
        }

        if (DeviceCode != null) {

            if (!tokenReq.getGrantType().equals(Constants.DEVICE_FLOW_GRANT_TYPE)) {

                throw new IdentityOAuth2Exception("Invalid GrantType");

            } else {

                results = DeviceFlowPersistenceFactory.getInstance().getDeviceFlowDAO()
                        .getAuthenticationStatus(DeviceCode);
                Date date = new Date();
                deviceStatus = results.get(Constants.STATUS).toString();
                //validate device code
                if (deviceStatus.equals(Constants.NOT_EXIST)) {
                    throw new IdentityOAuth2Exception(DeviceErrorCodes.INVALID_REQUEST);
                } else if (deviceStatus.equals(Constants.EXPIRED)) {
                    throw new IdentityOAuth2Exception(DeviceErrorCodes.SubDeviceErrorCodes.EXPIRED_TOKEN);
                } else if (isValidDeviceCode(results, date)) {
                    throw new IdentityOAuth2Exception(DeviceErrorCodes.SubDeviceErrorCodes.EXPIRED_TOKEN);
                } else if (deviceStatus.equals(Constants.AUTHORIZED)) {
                    authStatus = true;
                    DeviceFlowPersistenceFactory.getInstance().getDeviceFlowDAO().setDeviceCodeExpired(DeviceCode,
                            Constants.EXPIRED);
                    if (results.get(Constants.SCOPE) != null) {
                        String authzUser = results.get(Constants.AUTHZ_USER).toString();
                        String[] scopeSet = OAuth2Util.buildScopeArray(results.get(Constants.SCOPE).toString());
                        this.setPropertiesForTokenGeneration(oAuthTokenReqMessageContext, tokenReq, scopeSet,
                                authzUser);
                    }
                } else if (deviceStatus.equals(Constants.USED) || deviceStatus.equals(Constants.PENDING)) {
                    Timestamp newPollTime = new Timestamp(date.getTime());
                    if (isValidPollTime(newPollTime, results)) {
                        DeviceFlowPersistenceFactory.getInstance().getDeviceFlowDAO()
                                .setLastPollTime(DeviceCode, newPollTime);
                        throw new IdentityOAuth2Exception(DeviceErrorCodes.SubDeviceErrorCodes.AUTHORIZATION_PENDING);
                    } else {
                        DeviceFlowPersistenceFactory.getInstance().getDeviceFlowDAO()
                                .setLastPollTime(DeviceCode, newPollTime);
                        throw new IdentityOAuth2Exception(DeviceErrorCodes.SubDeviceErrorCodes.SLOW_DOWN);
                    }
                }
            }
        }
        return authStatus;
    }

    /**
     * Validate whether the claimed user is the rightful resource owner.
     *
     * @param tokReqMsgCtx Token request message context
     * @return true
     * @throws IdentityOAuth2Exception
     */
    public boolean authorizeAccessDelegation(OAuthTokenReqMessageContext tokReqMsgCtx)
            throws IdentityOAuth2Exception {

        return true;
    }

    /**
     * Validate whether scope requested by the access token is valid.
     *
     * @param tokReqMsgCtx Token request message context
     * @return true
     * @throws IdentityOAuth2Exception
     */
    public boolean validateScope(OAuthTokenReqMessageContext tokReqMsgCtx)
            throws IdentityOAuth2Exception {

        // if we need to just ignore the scope verification
        return true;
    }

    /**
     * To set the properties of the token generation.
     *
     * @param tokReqMsgCtx Token request message context
     * @param tokenReq Token request
     * @param scopes  Scopes that will be stored against token
     * @param authzUser Authorized user
     */
    private void setPropertiesForTokenGeneration(OAuthTokenReqMessageContext tokReqMsgCtx,
                                                 OAuth2AccessTokenReqDTO tokenReq, String[] scopes, String authzUser) {

        tokReqMsgCtx.setAuthorizedUser(OAuth2Util.getUserFromUserName(authzUser));
        tokReqMsgCtx.setScope(scopes);
    }

    @Override
    public OAuth2AccessTokenRespDTO issue(OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception {

        OAuth2AccessTokenRespDTO tokenRespDTO = super.issue(tokReqMsgCtx);
        return tokenRespDTO;
    }

    /**
     * This method use to check whether device code is expired or not
     *
     * @param results Result map that contains values from database
     * @param date Time that request has came
     * @return true or false
     */
    public static boolean isValidDeviceCode(HashMap results, Date date) {

        return Long.parseLong((String) results.get(Constants.EXPIRY_TIME)) < date.getTime();
    }

    /**
     * This checks whether polling frequency is correct or not
     *
     * @param newPollTime Time of the new poll request
     * @param results Result map that contains values from database
     * @return true or false
     */
    private static boolean isValidPollTime(Timestamp newPollTime, HashMap results) {

        return newPollTime.getTime() - Timestamp.valueOf((String) results.get(Constants.LAST_POLL_TIME))
                .getTime() > Long.parseLong(results.get(Constants.POLL_TIME).toString());
    }
}


