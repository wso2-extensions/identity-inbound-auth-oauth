/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.oauth2.cimd;

import java.util.Collections;
import java.util.List;

/**
 * Values taken from a validated Client ID Metadata Document.
 */
public class ClientIdMetadataDocument {

    private final String clientId;
    private final String clientName;
    private final String clientUri;
    private final List<String> redirectUris;
    private final String tokenEndpointAuthMethod;
    private final String jwksUri;
    private final List<String> grantTypes;

    public ClientIdMetadataDocument(String clientId, String clientName, String clientUri, List<String> redirectUris,
                                    String tokenEndpointAuthMethod, String jwksUri, List<String> grantTypes) {

        this.clientId = clientId;
        this.clientName = clientName;
        this.clientUri = clientUri;
        this.redirectUris = Collections.unmodifiableList(redirectUris);
        this.tokenEndpointAuthMethod = tokenEndpointAuthMethod;
        this.jwksUri = jwksUri;
        this.grantTypes = Collections.unmodifiableList(grantTypes);
    }

    public String getClientId() {

        return clientId;
    }

    public String getClientName() {

        return clientName;
    }

    public String getClientUri() {

        return clientUri;
    }

    public List<String> getRedirectUris() {

        return redirectUris;
    }

    public String getTokenEndpointAuthMethod() {

        return tokenEndpointAuthMethod;
    }

    public String getJwksUri() {

        return jwksUri;
    }

    public List<String> getGrantTypes() {

        return grantTypes;
    }
}
