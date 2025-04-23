/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.oauth2.finegrainedauthz.models;

/**
 * FineGrainedAuthzConfig is a model class that represents the configuration for fine-grained authorization.
 * It contains a flag to enable or disable fine-grained authorization.
 */
public class FineGrainedAuthzConfig {

    // A flag to enable or disable fine-grained authorization.
    private boolean enableFineGrainedAuthz;

    /**
     * Gets the current status of fine-grained authorization configuration.
     *
     * @return true if fine-grained authorization is enabled, false otherwise.
     */
    public boolean isEnableFineGrainedAuthz() {

        return enableFineGrainedAuthz;
    }

    /**
     * Sets the status of fine-grained authorization configuration.
     *
     * @param enableFineGrainedAuthz true to enable fine-grained authorization, false to disable it.
     */
    public void setEnableFineGrainedAuthz(boolean enableFineGrainedAuthz) {

        this.enableFineGrainedAuthz = enableFineGrainedAuthz;
    }
}
