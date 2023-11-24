/**
 * Copyright (c) 2023, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
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

package org.wso2.carbon.identity.oauth.par.dao;

import org.wso2.carbon.identity.oauth.par.exceptions.ParCoreException;
import org.wso2.carbon.identity.oauth.par.model.ParRequestDO;

import java.util.Map;
import java.util.Optional;

/**
 * DAO layer for PAR.
 */
public interface ParMgtDAO {

    /**
     * Persists the ParAuthRequest.
     *
     * @param requestURIReference PAR request identifier.
     * @param clientId Client ID of request.
     * @param expiresIn Time request will expire.
     * @param parameters Parameters in request.
     * @throws ParCoreException Exception thrown from PAR Core Component.
     */
    void persistRequestData(String requestURIReference, String clientId, long expiresIn,
                            Map<String, String> parameters) throws ParCoreException;

    /**
     * Retrieve the ParAuthRequest.
     *
     * @param requestURIReference PAR request identifier.
     * @return Optional ParRequestDO instance.
     * @throws ParCoreException Exception thrown from PAR Core Component.
     */
    Optional<ParRequestDO> getRequestData(String requestURIReference) throws ParCoreException;

    /**
     * Remove record from cache and database.
     *
     * @param requestURIReference PAR request identifier.
     * @throws ParCoreException Exception thrown from PAR Core Component.
     */
    void removeRequestData(String requestURIReference) throws ParCoreException;

}
