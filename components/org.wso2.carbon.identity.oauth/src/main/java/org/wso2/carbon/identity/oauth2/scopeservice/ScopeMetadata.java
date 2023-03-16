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

/**
 * Represents the metadata of a scope.
 */
public class ScopeMetadata {

    // Identifier will be the unique name of the scope.
    String identifier;
    String displayName;
    String description;

    public ScopeMetadata() {
    }

    public ScopeMetadata(String identifier, String displayName, String description) {

        this.identifier = identifier;
        this.displayName = displayName;
        this.description = description;
    }

    public String getIdentifier() {

        return identifier;
    }

    public void setIdentifier(String identifier) {

        this.identifier = identifier;
    }

    public String getDisplayName() {

        return displayName;
    }

    public void setDisplayName(String displayName) {

        this.displayName = displayName;
    }

    public String getDescription() {

        return description;
    }

    public void setDescription(String description) {

        this.description = description;
    }

    public String toJSON() {

        return "{" +
                "\"identifier\": \"" + identifier + "\"," +
                "\"displayName\": \"" + displayName + "\"," +
                "\"description\": \"" + description + "\"" +
                "}";
    }
}
