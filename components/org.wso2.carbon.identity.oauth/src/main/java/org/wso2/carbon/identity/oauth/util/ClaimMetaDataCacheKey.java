/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wso2.carbon.identity.oauth.util;

import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.core.cache.CacheKey;

/**
 * Claim Meta Data Cache Key.
 */
public class ClaimMetaDataCacheKey extends CacheKey {

    private static final long serialVersionUID = -1695934146647205705L;

    private AuthenticatedUser authenticatedUser;

    public ClaimMetaDataCacheKey(AuthenticatedUser authenticatedUser) {
        this.authenticatedUser = authenticatedUser;
    }

    @Override
    public boolean equals(Object otherObject) {

        return otherObject instanceof ClaimMetaDataCacheKey &&
                authenticatedUser.equals(((ClaimMetaDataCacheKey) otherObject).getAuthenticatedUser());
    }

    @Override
    public int hashCode() {
        return authenticatedUser != null ? authenticatedUser.hashCode() : 0;
    }

    public AuthenticatedUser getAuthenticatedUser() {
        return authenticatedUser;
    }

    public void setAuthenticatedUser(AuthenticatedUser authenticatedUser) {
        this.authenticatedUser = authenticatedUser;
    }
}
