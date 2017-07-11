/*
 *  Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.wso2.carbon.identity.oauth.cache;

public class OAuthScopeCacheKey extends CacheKey {

    private static final long serialVersionUID = -3480330645196653491L;
    private String scopeName;
    private String tenantID;

    public OAuthScopeCacheKey(String scopeName, String tenantID) {
        this.scopeName = scopeName;
        this.tenantID = tenantID;
    }

    public String getTenantID() {
        return tenantID;
    }

    public String getScopeName() {
        return scopeName;
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof OAuthScopeCacheKey)) {
            return false;
        }
        return ((this.scopeName.equals(((OAuthScopeCacheKey) o).getScopeName())) &&
                (this.tenantID.equals(((OAuthScopeCacheKey) o).getTenantID())));
    }

    @Override
    public int hashCode() {
        return (scopeName + tenantID).hashCode();
    }
}
