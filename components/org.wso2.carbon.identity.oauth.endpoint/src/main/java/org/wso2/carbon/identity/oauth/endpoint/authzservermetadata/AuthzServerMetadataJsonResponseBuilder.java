package org.wso2.carbon.identity.oauth.endpoint.authzservermetadata;

import com.google.gson.Gson;
import org.wso2.carbon.identity.discovery.OIDProviderConfigResponse;

import java.util.*;

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

