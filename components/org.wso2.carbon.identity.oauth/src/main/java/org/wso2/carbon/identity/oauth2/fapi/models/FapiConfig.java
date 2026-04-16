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

package org.wso2.carbon.identity.oauth2.fapi.models;

import java.util.List;

/**
 * The FapiConfig class handles the configuration for Financial-grade API (FAPI) settings.
 */
public class FapiConfig {

    private boolean enabled;
    private List<FapiProfileEnum> supportedProfiles;

    /**
     * Returns whether FAPI compliance enforcement is enabled for the tenant.
     *
     * @return true if FAPI enforcement is enabled, false otherwise.
     */
    public boolean isEnabled() {

        return enabled;
    }

    /**
     * Sets whether FAPI compliance enforcement is enabled for the tenant.
     *
     * @param enabled true to enable FAPI enforcement, false to disable it.
     */
    public void setEnabled(boolean enabled) {

        this.enabled = enabled;
    }

    /**
     * Returns the list of FAPI security profiles supported by the tenant.
     *
     * @return list of supported FAPI profile names.
     */
    public List<FapiProfileEnum> getSupportedProfiles() {

        return supportedProfiles;
    }

    /**
     * Sets the list of FAPI security profiles supported by the tenant.
     *
     * @param supportedProfiles list of supported FAPI profile names.
     */
    public void setSupportedProfiles(List<FapiProfileEnum> supportedProfiles) {

        this.supportedProfiles = supportedProfiles;
    }
}
