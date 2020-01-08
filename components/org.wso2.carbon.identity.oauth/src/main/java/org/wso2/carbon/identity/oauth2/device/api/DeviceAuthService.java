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

package org.wso2.carbon.identity.oauth2.device.api;

import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;

/**
 * Device authentication service.
 */
public interface DeviceAuthService {

    /**
     * Store device flow parameters and scopes in different tables.
     *
     * @param deviceCode Code that is used to identify the device.
     * @param userCode   Code that is used to correlate two devices.
     * @param clientId   Consumer key of the application.
     * @param scopes     Requested scopes.
     * @throws IdentityOAuth2Exception Error while storing device flow parameters.
     */
    void generateDeviceResponse(String deviceCode, String userCode, String clientId, String scopes)
            throws IdentityOAuth2Exception;

    /**
     * Store scopes in a different table.
     *
     * @param userCode Code that is used to correlate two devices.
     * @throws IdentityOAuth2Exception Error while storing scopes.
     */
    void setAuthenticationStatus(String userCode) throws IdentityOAuth2Exception;

    /**
     * Insert redirect uri to the database.
     *
     * @param clientId    Consumer key of the application.
     * @param redirectURI Redirection uri of the application.
     * @throws IdentityOAuth2Exception Error while storing redirect uri.
     */
    void setCallbackUri(String clientId, String redirectURI) throws IdentityOAuth2Exception;

    /**
     * Get client id for user code.
     *
     * @param userCode Code that is used to correlate two devices.
     * @return client id
     * @throws IdentityOAuth2Exception Error while getting client id for user code.
     */
    String getClientId(String userCode) throws IdentityOAuth2Exception;

    /**
     * Get scopes for user code.
     *
     * @param userCode Code that is used to correlate two devices.
     * @return scopes
     * @throws IdentityOAuth2Exception Error while getting scopes for user code.
     */
    String[] getScope(String userCode) throws IdentityOAuth2Exception;

    /**
     * Get status of the user code.
     *
     * @param userCode Code that is used to correlate two devices.
     * @return status of the user code.
     * @throws IdentityOAuth2Exception Error while getting the status.
     */
    String getStatus(String userCode) throws IdentityOAuth2Exception;

    /**
     * Validate client id.
     *
     * @param clientId Consumer key of the application.
     * @return true or false.
     * @throws IdentityOAuth2Exception Error while validate the client id.
     */
    boolean validateClientInfo(String clientId) throws IdentityOAuth2Exception;
}
