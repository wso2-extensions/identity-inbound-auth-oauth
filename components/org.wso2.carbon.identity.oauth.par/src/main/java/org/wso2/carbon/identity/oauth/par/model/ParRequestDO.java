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

package org.wso2.carbon.identity.oauth.par.model;

import java.util.Map;

/**
 * Contains PAR attributes that will be retrieved from the database.
 */
public class ParRequestDO {

    private Map<String, String> parameterMap;
    private long scheduledExpiryTime;
    private String clientId;

    public ParRequestDO (ParRequestCacheEntry parRequestCacheEntry) {

        this.parameterMap = parRequestCacheEntry.getParameterMap();
        this.scheduledExpiryTime = parRequestCacheEntry.getScheduledExpiryTime();
        this.clientId = parRequestCacheEntry.getClientId();
    }

    public ParRequestDO (Map<String, String> parameterMap, long scheduledExpiryTime, String clientId) {

        this.parameterMap = parameterMap;
        this.scheduledExpiryTime = scheduledExpiryTime;
        this.clientId = clientId;
    }

    public Map<String, String> getParameterMap() {
        return parameterMap;
    }

    public long getScheduledExpiryTime() {
        return scheduledExpiryTime;
    }

    public String getClientId() {
        return clientId;
    }


    public void setParameterMap(Map<String, String> parameterMap) {
        this.parameterMap = parameterMap;
    }

    public void setScheduledExpiryTime(long scheduledExpiryTime) {
        this.scheduledExpiryTime = scheduledExpiryTime;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }
}
