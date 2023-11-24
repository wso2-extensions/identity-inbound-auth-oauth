/*
 * Copyright (c) 2023, WSO2 LLC. (http://www.wso2.com).
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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.scopeservice;

import java.util.List;

/**
 * Represents the metadata of a resource.
 */
public class OAuth2Resource {

    String name;
    String id;
    List<ScopeMetadata> scopes;

    public OAuth2Resource() {

    }

    public OAuth2Resource(String name, String id, List<ScopeMetadata> scopes) {

        this.name = name;
        this.id = id;
        this.scopes = scopes;
    }

    public String getName() {

        return name;
    }

    public void setName(String name) {

        this.name = name;
    }

    public String getId() {

        return id;
    }

    public void setId(String id) {

        this.id = id;
    }

    public List<ScopeMetadata> getScopes() {

        return scopes;
    }

    public void setScopes(List<ScopeMetadata> scopes) {

        this.scopes = scopes;
    }

    public String toJSON() {

        StringBuilder builder = new StringBuilder();
        builder.append("{");
        builder.append("\"name\": \"").append(name).append("\",");
        builder.append("\"id\": \"").append(id).append("\",");
        builder.append("\"scopes\": [");
        for (ScopeMetadata scope : scopes) {
            builder.append(scope.toJSON()).append(",");
        }
        builder.deleteCharAt(builder.length() - 1);
        builder.append("]");
        builder.append("}");
        return builder.toString();
    }
}

