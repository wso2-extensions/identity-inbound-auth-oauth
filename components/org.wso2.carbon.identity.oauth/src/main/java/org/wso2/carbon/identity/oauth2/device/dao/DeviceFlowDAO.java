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

package org.wso2.carbon.identity.oauth2.device.dao;

import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;

import java.sql.Timestamp;
import java.util.HashMap;
import java.util.Map;

/**
 * New set of DAO classes  for each purpose  and factory class to get instance of each DAO classes were introduced
 * during  this step.
 */
public interface DeviceFlowDAO {

    /**
     * This will be used to enter the value to the database tables.
     *
     * @param deviceCode  Code that is used to identify the device
     * @param userCode    Code that is used to correlate user and device
     * @param consumerKey Consumer key of the client application
     * @param scope       Requesting scopes
     * @param expiresIn   Device code valid period
     * @throws IdentityOAuth2Exception
     */
    void insertDeviceFlow(String deviceCode, String userCode, String consumerKey, String scope, Long expiresIn) throws
            IdentityOAuth2Exception;

    /**
     * Get the client id that has involved with user code.
     *
     * @param userCode Code that is used to correlate user and device
     * @return client_id
     * @throws IdentityOAuth2Exception
     */
    String getClientIdByUserCode(String userCode) throws IdentityOAuth2Exception;

    /**
     * Set the status of the user code and device code.
     *
     * @param userCode Code that is used to correlate user and device
     * @param status   Status of the device and user codes
     * @throws IdentityOAuth2Exception
     */
    void setUserAuthenticated(String userCode, String status) throws IdentityOAuth2Exception;

    /**
     * Get the client id that has involved with user code.
     *
     * @param deviceCode Code that is used to identify the device
     * @throws IdentityOAuth2Exception
     */
    String getClientIdByDeviceCode(String deviceCode) throws IdentityOAuth2Exception;

    /**
     * Get the authentication status for device code.
     *
     * @param deviceCode Code that is used to identify the device
     * @return Map of values
     * @throws IdentityOAuth2Exception
     */
    Map getAuthenticationStatus(String deviceCode) throws IdentityOAuth2Exception;

    /**
     * Check client id is exist or not.
     *
     * @param clientId Consumer key of the application
     * @return Exist or not
     * @throws IdentityOAuth2Exception
     */
    boolean checkClientIdExist(String clientId) throws IdentityOAuth2Exception;

    /**
     * Get the scopes that are stored against user code.
     *
     * @param userCode Code that is used to correlate user and device
     * @return scope
     * @throws IdentityOAuth2Exception
     */
    String getScopeForDevice(String userCode) throws IdentityOAuth2Exception;

    /**
     * Get the status of the user code.
     *
     * @param userCode Code that is used to correlate user and device
     * @return status
     * @throws IdentityOAuth2Exception
     */
    String getStatusForUserCode(String userCode) throws IdentityOAuth2Exception;

    /**
     * Set last poll time of the token request.
     *
     * @param deviceCode  Code that is used to identify the device
     * @param newPollTime Last poll time
     * @throws IdentityOAuth2Exception
     */
    void setLastPollTime(String deviceCode, Timestamp newPollTime) throws IdentityOAuth2Exception;

    /**
     * Set authenticated user.
     *
     * @param userCode Code that is used to correlate user and device
     * @param userName Name of the authenticated user
     * @throws IdentityOAuth2Exception
     */
    void setAuthzUser(String userCode, String userName) throws IdentityOAuth2Exception;

    /**
     * Set device code as expired.
     *
     * @param deviceCode Code that is used to identify the device
     * @param status     Status of the device code
     * @throws IdentityOAuth2Exception
     */
    void setDeviceCodeExpired(String deviceCode, String status) throws IdentityOAuth2Exception;

    void setCallBackURI(String clientId, String callBackUri) throws IdentityOAuth2Exception;

}
