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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.ciba.dao;

import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.oauth.ciba.exceptions.CibaCoreException;
import org.wso2.carbon.identity.oauth.ciba.model.CibaAuthCodeDO;

import java.sql.Timestamp;
import java.util.List;

/**
 * DAO layer for CIBA.
 */
public interface CibaMgtDAO {

    /**
     * Persists the status of the relevant CibAuthCode identified by the CibaAuthCodeKey.
     *
     * @param authCodeKey          Identifier for CibaAuthCode.
     * @param authenticationStatus Status of the relevant CIBA Authentication.
     * @throws CibaCoreException Exception thrown from CIBA core Component.
     */
    void updateStatus(String authCodeKey, Enum authenticationStatus) throws CibaCoreException;

    /**
     * Persists the authenticated_user and status of the relevant CibAuthCode identified by the CibaAuthCodeKey.
     *
     * @param authCodeKey       Identifier for CibaAuthCode.
     * @param authenticatedUser Authenticated user of the relevant CibaAuthCode.
     * @throws CibaCoreException Exception thrown from CIBA Core Component.
     */
    void persistAuthenticationSuccess(String authCodeKey, AuthenticatedUser authenticatedUser) throws CibaCoreException;

    /**
     * Returns CibaAuthCodeKey for the authentication request identifier.
     *
     * @param authreqID Authentication request identifier.
     * @return String Returns CibaAuthCodeKey mapped to authentication request identifier.
     * @throws CibaCoreException Exception thrown from CIBA core Component.
     */
    String getCibaAuthCodeKey(String authreqID) throws CibaCoreException;

    /**
     * Updates the last polled time of tokenRequest.
     *
     * @param authCodeKey    Identifier of CibaAuthCode.
     * @param lastPolledTime CurrentTime in milliseconds.
     * @throws CibaCoreException Exception thrown from CIBA core Component.
     */
    void updateLastPollingTime(String authCodeKey, Timestamp lastPolledTime) throws CibaCoreException;

    /**
     * Updates the polling Interval of tokenRequest.
     *
     * @param authCodeKey identifier of CibaAuthCode.
     * @param newInterval Updated polling frequency.
     * @throws CibaCoreException Exception thrown from CIBA core Component.
     */
    void updatePollingInterval(String authCodeKey, long newInterval) throws CibaCoreException;

    /**
     * Returns the authenticated user of authenticationRequest.
     *
     * @param authCodeKey identifier of CibaAuthCode.
     * @return Returns AuthenticatedUser.
     * @throws CibaCoreException Exception thrown from CIBA core Component.
     */
    AuthenticatedUser getAuthenticatedUser(String authCodeKey) throws CibaCoreException;

    /**
     * Persists the CibaAuthCodeDO.
     *
     * @param cibaAuthCodeDO Data object that accumulates  CibaAuthCode.
     * @throws CibaCoreException Exception thrown from CIBA core Component.
     */
    void persistCibaAuthCode(CibaAuthCodeDO cibaAuthCodeDO) throws CibaCoreException;

    /**
     * Returns CibaAuthCodeDO identified by unique cibaAuthCodeKey.
     *
     * @param authCodeKey identifier of CibaAuthCode.
     * @throws CibaCoreException Exception thrown from CIBA core Component.
     */
    CibaAuthCodeDO getCibaAuthCode(String authCodeKey) throws CibaCoreException;

    /**
     * Retrieve scopes requested in CIBA authentication request.
     *
     * @param authCodeKey identifier of CibaAuthCode.
     * @throws CibaCoreException Exception thrown from CIBA core Component.
     */
    List<String> getScopes(String authCodeKey) throws CibaCoreException;

}
