/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
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

package org.wso2.carbon.identity.discovery;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.core.util.IdentityUtil;

/**
 * Utility to handle OIDC Discovery related functionality.
 */
public class DiscoveryUtil {

    public static final String OIDC_USE_ENTITY_ID_AS_ISSUER_IN_DISCOVERY = "OAuth" +
            ".UseEntityIdAsIssuerInOidcDiscovery";

    /**
     * Resident Idp entity id is honoured as the OIDC issuer location based on the configuration. This addresses
     * the issue <a href="https://github.com/wso2/product-is/issues/4277">wso2/product-is#4277</a>.
     */
    public static boolean isUseEntityIdAsIssuerInOidcDiscovery() {

        String useEntityIdAsIssuerInDiscovery =
                IdentityUtil.getProperty(OIDC_USE_ENTITY_ID_AS_ISSUER_IN_DISCOVERY);
        if (StringUtils.isEmpty(useEntityIdAsIssuerInDiscovery)) {
            return true;
        }
        return Boolean.parseBoolean(useEntityIdAsIssuerInDiscovery);
    }
}
