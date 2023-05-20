/**
 * Copyright (c) 2023, WSO2 LLC. (https://www.wso2.com). All Rights Reserved.
 * <p>
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.par.dao;


import org.wso2.carbon.identity.oauth.par.exceptions.ParCoreException;
import org.wso2.carbon.identity.oauth.par.model.ParRequestDO;

import java.util.Map;

/**
 * DAO layer for PAR.
 */
public interface ParMgtDAO {

    /**
     * Persists the ParAuthRequest.
     *
     * @param uuid Authentication request identifier.
     * @throws ParCoreException Exception thrown from PAR Core Component.
     */
    void persistParRequest(String uuid, String clientId, long scheduledExpiryTime,
                           Map<String, String> parameters) throws ParCoreException;

    ParRequestDO getParRequest(String uuid) throws ParCoreException;

    void removeParRequestData(String uuid) throws ParCoreException;

}
