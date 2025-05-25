/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.org).
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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.endpoint.authzservermetadata;

import com.google.gson.Gson;
import org.wso2.carbon.identity.discovery.OIDProviderConfigResponse;

import java.util.Map;
import java.util.Set;
import java.util.HashSet;
import java.util.Arrays;

public class AuthzServerMetadataJsonResponseBuilder {

    private static final String[] AUTHZ_SERVER_METADATA_RESPONSE_ATTRIBUTES = {
            "issuer",
            "authorization_endpoint",
            "token_endpoint",
            "jwks_uri",
            "scopes_supported",
            "response_types_supported",
            "grant_types_supported",
            "response_modes_supported",
            "userinfo_endpoint",
            "registration_endpoint",
            "token_endpoint_auth_methods_supported",
            "token_endpoint_auth_signing_alg_values_supported",
            "revocation_endpoint",
            "revocation_endpoint_auth_methods_supported",
            "introspection_endpoint",
            "introspection_endpoint_auth_methods_supported",
            "code_challenge_methods_supported"
    };

    public String getAuthzServerMetadataConfigString(OIDProviderConfigResponse oidProviderConfigResponse) {

        Map<String, Object> configs = oidProviderConfigResponse.getConfigMap();

        Set<String> allowedKeys = new HashSet<>(Arrays.asList(AUTHZ_SERVER_METADATA_RESPONSE_ATTRIBUTES));
        configs.keySet().retainAll(allowedKeys);

        return new Gson().toJson(configs);
    }
}

