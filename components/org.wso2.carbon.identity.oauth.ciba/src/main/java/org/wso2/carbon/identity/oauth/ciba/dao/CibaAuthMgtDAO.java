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

import org.wso2.carbon.identity.oauth.ciba.exceptions.CibaCoreException;
import org.wso2.carbon.identity.oauth.ciba.model.CibaAuthCodeDO;

/**
 * Abstracts DAO layer.
 */
public interface CibaAuthMgtDAO {

    /**
     * Persists the status of the relevant CibAuthCode identified by the CibaAuthCodeDOKey.
     *
     * @param cibaAuthCodeDOKey       Identifier for CibaAuthCodeDOKey.
     * @param cibaAuthentcationStatus Status of the relevant Ciba Authentication.
     * @throws CibaCoreException Exception thrown from CibaCore Component.
     */
    void persistStatus(String cibaAuthCodeDOKey, String cibaAuthentcationStatus) throws CibaCoreException;

    /**
     * Persists the authenticated_user of the relevant CibAuthCode identified by the CibaAuthCodeDOKey.
     *
     * @param cibaAuthCodeDOKey     Identifier for CibaAuthCode.
     * @param cibaAuthenticatedUser Authenticated_user of the relevant CibaAuthCode.
     * @throws CibaCoreException Exception thrown from CibaCore Component.
     */
    void persistUser(String cibaAuthCodeDOKey, String cibaAuthenticatedUser) throws CibaCoreException;

    /**
     * checks whether hash of CibaAuthReqId exists.
     *
     * @param hashedCibaAuthReqId hash of CibaAuthReqId.
     * @return boolean Returns whether given HashedAuthReqId present or not.
     * @throws CibaCoreException Exception thrown from CibaCore Component.
     */
    boolean isHashedAuthReqIDExists(String hashedCibaAuthReqId) throws CibaCoreException;

    /**
     * Returns CibaAuthCodeDOKey for the hash of CibaAuthReqId.
     *
     * @param hashedCibaAuthReqId hash of CibaAuthReqId.
     * @return String Returns CibaAuthCodeDOKey.
     * @throws CibaCoreException Exception thrown from CibaCore Component.
     */
    String getCibaAuthCodeDOKey(String hashedCibaAuthReqId) throws CibaCoreException;

    /**
     * Returns the lastPolledTime of tokenRequest.
     *
     * @param cibaAuthCodeDOKey Identifier of CibaAuthCodeDO.
     * @return long Returns lastPolledTime.
     * @throws CibaCoreException Exception thrown from CibaCore Component.
     */
    long getLastPolledTime(String cibaAuthCodeDOKey) throws CibaCoreException;

    /**
     * Returns the pollingInterval of tokenRequest.
     *
     * @param cibaAuthCodeDOKey identifier of CibaAuthReqId.
     * @return long Returns pollingInterval of tokenRequest.
     * @throws CibaCoreException Exception thrown from CibaCore Component.
     */
    long getPollingInterval(String cibaAuthCodeDOKey) throws CibaCoreException;

    /**
     * Updates the last polled time of tokenRequest.
     *
     * @param cibaAuthCodeDOKey Identifier of CibaAuthCodeDO.
     * @param currentTime       CurrentTime in milliseconds.
     * @throws CibaCoreException Exception thrown from CibaCore Component.
     */
    void updateLastPollingTime(String cibaAuthCodeDOKey, long currentTime) throws CibaCoreException;

    /**
     * Updates the polling Interval of tokenRequest.
     *
     * @param cibaAuthCodeDOKey identifier of CibaAuthCode.
     * @param newInterval       Updated polling frequency.
     * @throws CibaCoreException Exception thrown from CibaCore Component.
     */
    void updatePollingInterval(String cibaAuthCodeDOKey, long newInterval) throws CibaCoreException;

    /**
     * Returns authenticationStatus of authenticationRequest.
     *
     * @param cibaAuthCodeDOKey identifier of CibaAuthCodeDO.
     * @return String Returns AuthenticationStatus.
     * @throws CibaCoreException Exception thrown from CibaCore Component.
     */
    String getAuthenticationStatus(String cibaAuthCodeDOKey) throws CibaCoreException;

    /**
     * Returns the authenticated user of authenticationRequest.
     *
     * @param cibaAuthCodeDOKey identifier of CibaAuthCode
     * @return Returns AuthenticatedUser.
     * @throws CibaCoreException Exception thrown from CibaCore Component.
     */
    String getAuthenticatedUser(String cibaAuthCodeDOKey) throws CibaCoreException;

    /**
     * Persists the CibaAuthCodeDO.
     *
     * @param cibaAuthCodeDO Data object that accumulates  CibaAuthCode.
     * @throws CibaCoreException Exception thrown from CibaCore Component.
     */
    void persistCibaAuthCode(CibaAuthCodeDO cibaAuthCodeDO) throws CibaCoreException;

    /**
     * Returns CibaAuthCodeDO identified by unique cibaAuthCodeDOKey.
     *
     * @param cibaAuthCodeDOKey Identifier of CibaAuthCode.
     * @throws CibaCoreException Exception thrown from CibaCore Component.
     */
    CibaAuthCodeDO getCibaAuthCodeDO(String cibaAuthCodeDOKey) throws CibaCoreException;

}
