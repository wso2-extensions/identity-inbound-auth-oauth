/*
 * Copyright (c) 2023, WSO2 LLC. (https://www.wso2.com).
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

package org.wso2.carbon.identity.oauth.par.model;

import org.apache.commons.collections.MapUtils;

import java.util.HashMap;
import java.util.Map;

/**
 * Contains PAR attributes that will be retrieved from the database.
 */
public class ParRequestDO {

    private Map<String, String> params;
    private long expiresIn;
    private String clientId;

    /**
     * Constructor with variables obtained from DAO to ParRequestDO.
     *
     * @param parameterMap Parameter map.
     * @param expiresIn    Scheduled expiry time.
     * @param clientId     Client id.
     */
    public ParRequestDO(Map<String, String> parameterMap, long expiresIn, String clientId) {

        this.params = MapUtils.isEmpty(parameterMap) ? new HashMap<>() : parameterMap;
        this.expiresIn = expiresIn;
        this.clientId = clientId;
    }

    /**
     * Get parameter map.
     *
     * @return Map of params.
     */
    public Map<String, String> getParams() {

        return params;
    }

    /**
     * Get scheduled expiry time.
     *
     * @return Scheduled expiry time.
     */
    public long getExpiresIn() {

        return expiresIn;
    }

    /**
     * Get client id.
     *
     * @return Client id.
     */
    public String getClientId() {

        return clientId;
    }

    /**
     * Set parameter map.
     *
     * @param params Parameter map.
     */
    public void setParams(Map<String, String> params) {

        this.params = params;
    }

    /**
     * Set scheduled expiry.
     *
     * @param expiresIn Scheduled expiry.
     */
    public void setExpiresIn(long expiresIn) {

        this.expiresIn = expiresIn;
    }

    /**
     * Set client id.
     *
     * @param clientId Client id.
     */
    public void setClientId(String clientId) {

        this.clientId = clientId;
    }
}
