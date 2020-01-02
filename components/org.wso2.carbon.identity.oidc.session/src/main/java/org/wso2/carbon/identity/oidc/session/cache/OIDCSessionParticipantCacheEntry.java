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

import org.wso2.carbon.identity.application.common.cache.CacheEntry;
import org.wso2.carbon.identity.oidc.session.OIDCSessionState;

/**
 * This class holds OIDC session information and gets cached against a cache key.
 */
public class OIDCSessionParticipantCacheEntry extends CacheEntry {

    private static final long serialVersionUID = -4119009067955456678L;

    private OIDCSessionState sessionState;

    /**
     * Returns session state information which includes authenticated user, and clients authenticated for that user
     * who participates in the same browser session.
     *
     * @return OIDCSessionState instance
     */
    public OIDCSessionState getSessionState() {

        return sessionState;
    }

    /**
     * Sets the session state.
     *
     * @param sessionState OIDCSessionState instance
     */
    public void setSessionState(OIDCSessionState sessionState) {

        this.sessionState = sessionState;
    }
}
