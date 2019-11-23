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

/**
 * DAO layer for CIBA.
 */
public interface CibaAuthMgtDAO {

    /**
     * Persists the status of the relevant CibAuthCode identified by the CibaAuthCodeDOKey.
     *
     * @param key                  Identifier for CibaAuthCode.
     * @param authenticationStatus Status of the relevant CIBA Authentication.
     * @throws CibaCoreException Exception thrown from CIBA core Component.
     */
    void updateStatus(String key, Enum authenticationStatus) throws CibaCoreException;

    /**
     * Persists the authenticated_user of the relevant CibAuthCode identified by the CibaAuthCodeDOKey.
     *
     * @param key               Identifier for CibaAuthCode.
     * @param authenticatedUser Authenticated user of the relevant CibaAuthCode.
     * @param tenantID          Tenant ID.
     * @throws CibaCoreException Exception thrown from CIBA Core Component.
     */
    void persistAuthenticatedUser(String key, AuthenticatedUser authenticatedUser, int tenantID)
            throws CibaCoreException;

    /**
     * Persists the authenticated_user and status of the relevant CibAuthCode identified by the CibaAuthCodeDOKey.
     *
     * @param key               Identifier for CibaAuthCode.
     * @param idpID             Authenticated Identity provider identifier.
     * @param authenticatedUser Authenticated user of the relevant CibaAuthCode.
     * @param tenantID          Tenant ID.
     * @throws CibaCoreException Exception thrown from CIBA Core Component.
     */
    void persistAuthenticationSuccess(String key, int idpID, AuthenticatedUser authenticatedUser, int tenantID)
            throws CibaCoreException;

    /**
     * Checks whether hash of CibaAuthCode exists.
     *
     * @param authReqId hash of CibaAuthReqID.
     * @return boolean Returns whether given HashedAuthReqId present or not.
     * @throws CibaCoreException Exception thrown from CibaCore Component.
     */
    boolean isAuthReqIDExist(String authReqId) throws CibaCoreException;

    /**
     * Returns CibaAuthCodeKey for the authentication request identifier.
     *
     * @param authreqID Authentication request identifier.
     * @return String Returns CibaAuthCodeKey.
     * @throws CibaCoreException Exception thrown from CIBA core Component.
     */
    String getCibaAuthCodeKey(String authreqID) throws CibaCoreException;

    /**
     * Updates the last polled time of tokenRequest.
     *
     * @param key            Identifier of CibaAuthCodeDO.
     * @param lastPolledTime CurrentTime in milliseconds.
     * @throws CibaCoreException Exception thrown from CIBA core Component.
     */
    void updateLastPollingTime(String key, Timestamp lastPolledTime) throws CibaCoreException;

    /**
     * Updates the polling Interval of tokenRequest.
     *
     * @param key         identifier of CibaAuthCode.
     * @param newInterval Updated polling frequency.
     * @throws CibaCoreException Exception thrown from CIBA core Component.
     */
    void updatePollingInterval(String key, long newInterval) throws CibaCoreException;

    /**
     * Returns authenticationStatus of authenticationRequest.
     *
     * @param key identifier of CibaAuthCode.
     * @return String Returns AuthenticationStatus.
     * @throws CibaCoreException Exception thrown from CIBA core Component.
     */
    Enum getAuthenticationStatus(String key) throws CibaCoreException;

    /**
     * Returns the authenticated user of authenticationRequest.
     *
     * @param cibaAuthCodeDOKey identifier of CibaAuthCode
     * @return Returns AuthenticatedUser.
     * @throws CibaCoreException Exception thrown from CIBA core Component.
     */
    AuthenticatedUser getAuthenticatedUser(String cibaAuthCodeDOKey) throws CibaCoreException;

    /**
     * Persists the CibaAuthCodeDO.
     *
     * @param cibaAuthCodeDO Data object that accumulates  CibaAuthCode.
     * @throws CibaCoreException Exception thrown from CIBA core Component.
     */
    void persistCibaAuthCode(CibaAuthCodeDO cibaAuthCodeDO) throws CibaCoreException;

    /**
     * Returns CibaAuthCodeDO identified by unique cibaAuthCodeDOKey.
     *
     * @param authReqID CIBA Authentication request identifier.
     * @throws CibaCoreException Exception thrown from CIBA core Component.
     */
    CibaAuthCodeDO getCibaAuthCodeWithAuhReqID(String authReqID) throws CibaCoreException;

    /**
     * Store scopes requested in CIBA authentication request.
     *
     * @param cibaAuthCodeDO CibaAuthCode Data Object.
     * @throws CibaCoreException Exception thrown from CIBA core Component.
     */
    void storeScope(CibaAuthCodeDO cibaAuthCodeDO) throws CibaCoreException;

    /**
     * Retrieve scopes requested in CIBA authentication request.
     *
     * @param cibaAuthCodeDO CibaAuthCode Data Object.
     * @throws CibaCoreException Exception thrown from CIBA core Component.
     */
    String[] getScope(CibaAuthCodeDO cibaAuthCodeDO) throws CibaCoreException;

    /**
     * Update status with available authentication request identifier.
     *
     * @param authReqID            Authentication request identifier.
     * @param authenticationStatus Authentication Status.
     * @throws CibaCoreException Exception thrown from CIBA core Component.
     */
    void updateStatusWithAuthReqID(String authReqID, Enum authenticationStatus) throws CibaCoreException;

    /**
     * Obtain idp id from idp name.
     *
     * @param idpName Name of Identity provider.
     * @return Identity provider identifier.
     * @throws CibaCoreException Exception thrown from CIBA core Component.
     */
    int getIdpID(String idpName) throws CibaCoreException;
}
