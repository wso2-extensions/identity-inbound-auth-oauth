/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oidc.session.cache;

import org.wso2.carbon.identity.application.common.cache.CacheKey;

/**
 * This class holds the cache key which is the browser session cookie id.
 */
public class OIDCSessionParticipantCacheKey extends CacheKey {

    private static final long serialVersionUID = 4550492346056924493L;

    private String sessionID;

    /**
     * Returns session id.
     *
     * @return session id value
     */
    public String getSessionID() {

        return sessionID;
    }

    /**
     * Sets session id.
     *
     * @param sessionID session id value
     */
    public void setSessionID(String sessionID) {

        this.sessionID = sessionID;
    }

    @Override
    public boolean equals(Object o) {

        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        if (!super.equals(o)) {
            return false;
        }

        OIDCSessionParticipantCacheKey that = (OIDCSessionParticipantCacheKey) o;

        if (!sessionID.equals(that.sessionID)) {
            return false;
        }

        return true;
    }

    @Override
    public int hashCode() {

        int result = super.hashCode();
        result = 31 * result + sessionID.hashCode();
        return result;
    }
}
