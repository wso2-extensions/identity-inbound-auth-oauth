/*
 * Copyright (c) 2024, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.oauth.endpoint.oidcdiscovery;

import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.discovery.builders.OIDProviderResponseBuilder;

/**
 * Service holder for managing instances of OIDC Discovery related services.
 */
public class OIDCDiscoveryServiceHolder {

    private static class OIDCProviderJSONResponseBuilderHolder {

        static final OIDProviderResponseBuilder SERVICE = (OIDProviderResponseBuilder) PrivilegedCarbonContext
                .getThreadLocalCarbonContext().getOSGiService(OIDProviderResponseBuilder.class, null);
    }

    public static OIDProviderResponseBuilder getOIDProviderResponseBuilder() {

        if (OIDCProviderJSONResponseBuilderHolder.SERVICE == null) {
            throw new IllegalStateException("OIDProviderJSONResponseBuilder is not available from OSGi context.");
        }
        return OIDCProviderJSONResponseBuilderHolder.SERVICE;
    }
}
