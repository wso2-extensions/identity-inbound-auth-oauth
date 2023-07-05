/**
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

import java.util.Map;

/**
 * Contains PAR attributes that will be retrieved from the database.
 */
public class ParRequestDO {

    private Map<String, String> params;
    private long scheduledExpiryTime;
    private String clientId;

    /**
     * Constructor with variables obtained from ParRequestCacheEntry object to ParRequestDO.
     *
     * @param parRequestCacheEntry cache entry for PAR request.
     */
    public ParRequestDO (ParRequestCacheEntry parRequestCacheEntry) {

        this.params = parRequestCacheEntry.getParams();
        this.scheduledExpiryTime = parRequestCacheEntry.getScheduledExpiryTime();
        this.clientId = parRequestCacheEntry.getClientId();
    }

    /**
     * Contractor with variables obtained from DAO to ParRequestDO.
     *
     * @param parameterMap parameter map
     * @param scheduledExpiryTime scheduled expiry time
     * @param clientId client id
     */
    public ParRequestDO (Map<String, String> parameterMap, long scheduledExpiryTime, String clientId) {

        this.params = parameterMap;
        this.scheduledExpiryTime = scheduledExpiryTime;
        this.clientId = clientId;
    }

    /**
     * Get parameter map.
     *
     * @return params
     */
    public Map<String, String> getParams() {

        return params;
    }

    /**
     * Get scheduled expiry time.
     *
     * @return scheduledExpiryTime
     */
    public long getScheduledExpiryTime() {

        return scheduledExpiryTime;
    }

    /**
     * Get client id.
     *
     * @return clientId
     */
    public String getClientId() {

        return clientId;
    }


    /**
     * Set parameter map.
     *
     * @param params parameter map
     */
    public void setParams(Map<String, String> params) {

        this.params = params;
    }

    /**
     * Set scheduled expiry.
     *
     * @param scheduledExpiryTime scheduled expiry
     */
    public void setScheduledExpiryTime(long scheduledExpiryTime) {

        this.scheduledExpiryTime = scheduledExpiryTime;
    }

    /**
     * Set client id.
     *
     * @param clientId client id
     */
    public void setClientId(String clientId) {

        this.clientId = clientId;
    }
}
