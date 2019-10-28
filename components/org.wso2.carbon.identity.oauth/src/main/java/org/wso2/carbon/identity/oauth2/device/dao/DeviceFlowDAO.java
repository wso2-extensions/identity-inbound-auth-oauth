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

/**
 * New set of DAO classes  for
 * each purpose  and factory class to get instance of each DAO classes were introduced  during  this step.
 */
public interface DeviceFlowDAO {

    /**
     * This will use to enter the value to the database tables
     *
     * @param deviceCode
     * @param userCode
     * @param consumerKey
     * @param scope
     * @param expiresIn
     * @throws IdentityOAuth2Exception
     */
    void insertDeviceFlow(String deviceCode, String userCode, String consumerKey, String scope, Long expiresIn) throws
            IdentityOAuth2Exception;

    /**
     * Get the client id that has involved with user code
     *
     * @param userCode
     * @return client id
     * @throws IdentityOAuth2Exception
     */
    String getClientIdByUSerCode(String userCode) throws IdentityOAuth2Exception;

    /**
     * Set the status of the user code and device code
     *
     * @param userCode
     * @param status
     * @throws IdentityOAuth2Exception
     */
    void setUserAuthenticated(String userCode, String status) throws IdentityOAuth2Exception;

    /**
     * Get the client id that has involved with user code
     *
     * @param deviceCode
     * @return
     * @throws IdentityOAuth2Exception
     */
    String getClientIdByDeviceCode(String deviceCode) throws IdentityOAuth2Exception;

    /**
     * Get the authentication status for device code
     *
     * @param deviceCode
     * @return map of values
     * @throws IdentityOAuth2Exception
     */
    HashMap getAuthenticationStatus(String deviceCode) throws IdentityOAuth2Exception;

    /**
     * Check client id is exist or not
     *
     * @param clientId
     * @return exist or not
     * @throws IdentityOAuth2Exception
     */
    boolean checkClientIdExist(String clientId) throws IdentityOAuth2Exception;

    /**
     * Get the scopes that are stored against user code
     *
     * @param userCode
     * @return scope
     * @throws IdentityOAuth2Exception
     */
    String getScopeForDevice(String userCode) throws IdentityOAuth2Exception;

    /**
     * Get the status of the user code
     *
     * @param userCode
     * @return status
     * @throws IdentityOAuth2Exception
     */
    String getStatusForUserCode(String userCode) throws IdentityOAuth2Exception;

    /**
     * Set last poll time of the token request
     *
     * @param deviceCode
     * @param newPollTime
     * @throws IdentityOAuth2Exception
     */
    void setLastPollTime(String deviceCode, Timestamp newPollTime) throws IdentityOAuth2Exception;

    /**
     * Set authenticated user
     * @param userCode
     * @param userName
     * @throws IdentityOAuth2Exception
     */
    void setAuthzUser(String userCode, String userName) throws IdentityOAuth2Exception;

    /**
     * Set device code as expired
     * @param deviceCode
     * @param status
     * @throws IdentityOAuth2Exception
     */
    void setDeviceCodeExpired(String deviceCode, String status) throws IdentityOAuth2Exception;

}
