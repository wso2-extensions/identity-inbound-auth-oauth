/**
 * Copyright (c) 2023, WSO2 LLC. (https://www.wso2.com). All Rights Reserved.
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.par.dao;


import org.wso2.carbon.identity.oauth.par.exceptions.ParClientException;
import org.wso2.carbon.identity.oauth.par.exceptions.ParCoreException;

import java.sql.SQLException;
import java.util.HashMap;

/**
 * DAO layer for PAR.
 */
public interface ParMgtDAO {

    /**
     * Persists the ParAuthRequest.
     *
     * @param reqUUID Authentication request identifier.
     * @throws ParCoreException Exception thrown from PAR Core Component.
     */
    void persistParRequestData(String reqUUID, String clientId, long reqMadeAt) throws ParCoreException, SQLException;

    /**
     * Persists the ParAuthRequest.
     *
     * @param reqUUID Authentication request identifier.
     * @throws ParCoreException Exception thrown from PAR Core Component.
     */
    void persistParRequestParams(String reqUUID, String paramKey, String paramValue) throws ParCoreException;

    /**
     * Persists the request object parameter.
     *
     * @param reqUUID Authentication request identifier.
     * @throws ParCoreException Exception thrown from PAR Core Component.
     */
    void persistRequestObject(String reqUUID, String request_object) throws ParCoreException;

    String getParClientId(String reqUUID) throws ParClientException;

    HashMap<String, String> getParParamMap(String reqUUID) throws ParClientException;

    String getRequestObject(String uuid) throws ParClientException;

    long getExpiresIn(String reqUUID) throws ParClientException;
}
