/*
 * Copyright (c) 2024-2026, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.oauth.dcr.model;

import org.wso2.carbon.identity.oauth2.fapi.models.FapiProfileEnum;

/**
 * DCR Configuration model.
 */
public class DCRConfiguration {

    private Boolean enableFapiEnforcement;
    private Boolean authenticationRequired;
    private Boolean mandateSSA;
    private String ssaJwks;
    private FapiProfileEnum fapiProfile;

    /**
     * Get the value of enableFapiEnforcement.
     *
     * @return enableFapiEnforcement
     */
    public Boolean getEnableFapiEnforcement() {

        return enableFapiEnforcement;
    }

    /**
     * Get the value of authenticationRequired.
     *
     * @return authenticationRequired
     */
    public Boolean getAuthenticationRequired() {

        return authenticationRequired;
    }

    /**
     * Get the value of mandateSSA.
     *
     * @return mandateSSA
     */
    public Boolean getMandateSSA() {

        return mandateSSA;
    }

    /**
     * Get the value of ssaJwks.
     *
     * @return ssaJwks
     */
    public String getSsaJwks() {

        return ssaJwks;
    }

    /**
     * Set the value of enableFapiEnforcement.
     *
     * @param enableFapiEnforcement The value to set.
     */
    public void setEnableFapiEnforcement(Boolean enableFapiEnforcement) {

        this.enableFapiEnforcement = enableFapiEnforcement;
    }

    /**
     * Set the value of authenticationRequired.
     *
     * @param authenticationRequired The value to set.
     */
    public void setAuthenticationRequired(Boolean authenticationRequired) {

        this.authenticationRequired = authenticationRequired;
    }

    /**
     * Set the value of mandateSSA.
     *
     * @param mandateSSA The value to set.
     */
    public void setMandateSSA(Boolean mandateSSA) {

        this.mandateSSA = mandateSSA;
    }

    /**
     * Set the value of ssaJwks.
     *
     * @param ssaJwks The value to set.
     */
    public void setSsaJwks(String ssaJwks) {

        this.ssaJwks = ssaJwks;
    }

    /**
     * Get the value of fapiProfile.
     *
     * @return FapiProfileEnum instance.
     */
    public FapiProfileEnum getFapiProfile() {

        return this.fapiProfile;
    }

    /**
     * Set the value of fapiProfile.
     *
     * @param fapiProfile The value to set.
     */
    public void setFapiProfile(FapiProfileEnum fapiProfile) {

        this.fapiProfile = fapiProfile;
    }
}
