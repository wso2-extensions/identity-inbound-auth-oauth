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

package org.wso2.carbon.identity.oauth.par.dao;


import org.apache.oltu.oauth2.as.request.OAuthAuthzRequest;
import org.wso2.carbon.identity.oauth.par.exceptions.ParCoreException;
import org.wso2.carbon.identity.oauth.par.model.ParDataRecord;

import java.io.Serializable;
import java.sql.SQLException;

/**
 * DAO layer for PAR.
 */
public interface ParMgtDAO {

    /**
     * Persists the ParAuthRequest.
     *
     * @param parameters Data object that accumulates  par request data.
     */
    void persistParRequest(String reqUUID, String parameters, long reqMadeAt) throws ParCoreException, SQLException;

    /**
     * Returns ParAuthRequestObject identified by unique UUID of requestUri.
     *
     * @param reqUUID identifier of par request.
     */
    ParDataRecord getParRequestRecord(String reqUUID) throws ParCoreException;

}
