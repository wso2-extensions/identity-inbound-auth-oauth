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

import org.apache.commons.lang.NotImplementedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.device.model.DeviceFlowDO;

import java.sql.Timestamp;
import java.util.Optional;

/**
 * New set of DAO classes  for each purpose  and factory class to get instance of each DAO classes were introduced
 * during  this step.
 */
public interface DeviceFlowDAO {

    /**
     * This will be used to enter the values to the database tables and return the unique user_code.
     *
     * @param deviceCode  Code that is used to identify the device.
     * @param userCode    Code that is used to correlate user and device.
     * @param quantifier  Quantized time period user_code belongs.
     * @param consumerKey Consumer key of the client application.
     * @param scopes      Requested scopes.
     * @return Unique user_code.
     * @throws IdentityOAuth2Exception Error while inserting device flow parameters.
     */
    default String insertDeviceFlowParametersWithQuantifier(String deviceCode, String userCode, long quantifier,
        String consumerKey, String scopes) throws IdentityOAuth2Exception {

        throw new NotImplementedException("Not Implemented.");
    }

    /**
     * This will be used to enter the value to the database tables.
     * @deprecated
     * This method is no longer acceptable.
     * @link DeviceFlowDAO#insertDeviceFlowParametersWithQuantifier(String, String, long, String, String).
     *
     * @param deviceCode  Code that is used to identify the device.
     * @param userCode    Code that is used to correlate user and device.
     * @param consumerKey Consumer key of the client application.
     * @param expiresIn   Device code valid period.
     * @param interval    Polling interval.
     * @param scopes      Requested scopes.
     * @throws IdentityOAuth2Exception Error while inserting device flow parameters.
     */
    @Deprecated
    void insertDeviceFlowParameters(String deviceCode, String userCode, String consumerKey, Long expiresIn,
                                    int interval, String scopes) throws IdentityOAuth2Exception;

    /**
     * Get the client id that has involved with user code.
     *
     * @param userCode Code that is used to correlate user and device.
     * @return client_id
     * @throws IdentityOAuth2Exception Error while getting client id for user code.
     *
     * @deprecated because the client id of the user is included in {{{@link #getDetailsForUserCode(String)}}}.
     * Deprecated for removal.
     */
    @Deprecated
    String getClientIdByUserCode(String userCode) throws IdentityOAuth2Exception;

    /**
     * Set the status of the user code and device code.
     *
     * @param userCode Code that is used to correlate user and device.
     * @throws IdentityOAuth2Exception Error while setting authentication status.
     */
    default void setAuthenticationStatus(String userCode) throws IdentityOAuth2Exception {

        throw new NotImplementedException("Not Implemented.");
    }

    /**
     * Set the status of the user code and device code.
     * @deprecated
     * This method is no longer acceptable.
     * @link DeviceFlowDAO#setAuthenticationStatus(String).
     *
     * @param userCode Code that is used to correlate user and device.
     * @param status   Status of the device and user codes.
     * @throws IdentityOAuth2Exception Error while setting authentication status.
     */
    @Deprecated
    void setAuthenticationStatus(String userCode, String status) throws IdentityOAuth2Exception;

    /**
     * Get the authentication status for device code.
     *
     * @param deviceCode Code that is used to identify the device.
     * @param clientId   Consumer key of the application.
     * @return Map of values.
     * @throws IdentityOAuth2Exception Error while getting authentication details.
     */
    default DeviceFlowDO getAuthenticationDetails(String deviceCode, String clientId) throws IdentityOAuth2Exception {

        throw new NotImplementedException("Not Implemented.");
    }

    /**
     * Get the authentication status for device code.
     * @deprecated
     * This method is no longer acceptable.
     * @link DeviceFlowDAO#getAuthenticationDetails(String, String).
     *
     * @param deviceCode Code that is used to identify the device.
     * @return Map of values.
     * @throws IdentityOAuth2Exception Error while getting authentication details.
     */
    @Deprecated
    DeviceFlowDO getAuthenticationDetails(String deviceCode) throws IdentityOAuth2Exception;

    /**
     * Check client id is exist or not.
     *
     * @param clientId Consumer key of the application.
     * @return Exist or not.
     * @throws IdentityOAuth2Exception Error while checking client id exist.
     *
     * @deprecated because device flow DAO layer should not validate the client information.
     * Deprecated for removal.
     */
    @Deprecated
    boolean checkClientIdExist(String clientId) throws IdentityOAuth2Exception;

    /**
     * Get the status of the user code.
     *
     * @param userCode Code that is used to correlate user and device.
     * @return status
     * @throws IdentityOAuth2Exception Error while getting status for user code.
     *
     * @deprecated because the scopes of the user is included in {{{@link #getDetailsForUserCode(String)}}}.
     * Deprecated for removal.
     */
    @Deprecated
    String getStatusForUserCode(String userCode) throws IdentityOAuth2Exception;

    /**
     * Set last poll time of the token request.
     *
     * @param deviceCode  Code that is used to identify the device.
     * @param newPollTime Last poll time.
     * @throws IdentityOAuth2Exception Error while setting last poll time.
     */
    void setLastPollTime(String deviceCode, Timestamp newPollTime) throws IdentityOAuth2Exception;

    /**
     * Set authenticated user.
     *
     * @param userCode  Code that is used to correlate user and device.
     * @param status    Status of the device code.
     * @param authzUser Authenticated user.
     * @throws IdentityOAuth2Exception Error while setting authenticated user and status.
     */
    void setAuthzUserAndStatus(String userCode, String status, AuthenticatedUser authzUser)
            throws IdentityOAuth2Exception;

    /**
     * Set device code as expired.
     *
     * @param deviceCode Code that is used to identify the device.
     * @param status     Status of the device code.
     * @throws IdentityOAuth2Exception Error while setting device code as expired.
     */
    void setDeviceCodeExpired(String deviceCode, String status) throws IdentityOAuth2Exception;

    /**
     * Return device code for given user code.
     *
     * @param userCode Code that is used to correlate user and device.
     * @return Device code.
     * @throws IdentityOAuth2Exception Error while getting device code for user code.
     */
    default Optional<String> getDeviceCodeForUserCode(String userCode) throws IdentityOAuth2Exception {

        return Optional.empty();
    }

    /**
     * Set callback uri of the service provider.
     *
     * @param clientId    Consumer key of service provide.
     * @param callBackUri Callback uri of the service provider.
     * @throws IdentityOAuth2Exception Error while Setting callback uri.
     *
     * @deprecated because device flow DAO layer should not update application detail.
     * Deprecated for removal.
     */
    @Deprecated
    void setCallbackURI(String clientId, String callBackUri) throws IdentityOAuth2Exception;

    /**
     * Return scope array for user code.
     *
     * @param userCode Code that is used to correlate user and device.
     * @return Array of scopes.
     * @throws IdentityOAuth2Exception Error while getting scopes for user code.
     *
     * @deprecated because the scopes of the user is included in {{@link #getDetailsForUserCode(String)}}.
     * Deprecated for removal.
     */
    @Deprecated
    String[] getScopesForUserCode(String userCode) throws IdentityOAuth2Exception;

    /**
     * Return scope array for device code.
     *
     * @param deviceCode Code that is used to identify the device.
     * @return Array of scopes.
     * @throws IdentityOAuth2Exception Error while getting scopes for device code.
     *
     * @deprecated because the scopes of the device code is included in
     * {{@link #getAuthenticationDetails(String, String)}}.
     * Deprecated for removal.
     */
    @Deprecated
    String[] getScopesForDeviceCode(String deviceCode) throws IdentityOAuth2Exception;

    /**
     * Get details for user_code.
     *
     * @param userCode Code that is used to correlate user and device.
     * @return Map of values.
     * @throws IdentityOAuth2Exception Error while getting details for user code.
     */
    default DeviceFlowDO getDetailsForUserCode(String userCode) throws IdentityOAuth2Exception {

        throw new NotImplementedException("Not Implemented.");
    }
}
