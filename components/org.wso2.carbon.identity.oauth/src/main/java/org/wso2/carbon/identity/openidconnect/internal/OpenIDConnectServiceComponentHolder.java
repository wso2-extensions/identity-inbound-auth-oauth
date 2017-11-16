/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.openidconnect.internal;

import org.wso2.carbon.identity.openidconnect.OpenIDConnectClaimFilter;

import java.util.ArrayList;
import java.util.List;

public class OpenIDConnectServiceComponentHolder {

    private static OpenIDConnectServiceComponentHolder instance = new OpenIDConnectServiceComponentHolder();
    private List<OpenIDConnectClaimFilter> openIDConnectClaimFilters = new ArrayList<>();

    private OpenIDConnectServiceComponentHolder() {
    }

    public static OpenIDConnectServiceComponentHolder getInstance() {
        return instance;
    }

    /**
     *
     * @return The OIDC Claim Filter with the highest priority.
     */
    public OpenIDConnectClaimFilter getHighestPriorityOpenIDConnectClaimFilter() {
        if (openIDConnectClaimFilters.isEmpty()) {
            throw new RuntimeException("No OpenIDConnect Claim Filters available.");
        }
        return openIDConnectClaimFilters.get(0);
    }

    public List<OpenIDConnectClaimFilter> getOpenIDConnectClaimFilters() {
        return openIDConnectClaimFilters;
    }
}
