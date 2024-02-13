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

package org.wso2.carbon.identity.oauth.dcr.model;

import org.wso2.carbon.identity.oauth.dcr.exception.DCRMServerException;

/**
 * DCR Configuration model.
 */
public class DCRConfiguration {

    private Boolean isDCRFAPIEnforced;
    private Boolean clientAuthenticationRequired;
    private String ssaJwks;
    private String mandateSSA;

    public String getMandateSSA() {

        return mandateSSA;
    }

    /**
     * Set the value of mandateSSA.
     * We only accept "true", "false" or null as valid values for this mandateSSA field.
     *
     * @param mandateSSA The value to set.
     */
    public void setMandateSSA(String mandateSSA) throws DCRMServerException {

        if (mandateSSA == null || "true".equals(mandateSSA) || "false".equals(mandateSSA)) {
            this.mandateSSA = mandateSSA;
        } else {
            throw new DCRMServerException("Invalid value for mandateSSA: " + mandateSSA);
        }

    }

    public Boolean isFAPIEnforced() {

        return isDCRFAPIEnforced;
    }

    public void setFAPIEnforced(Boolean isDCRFAPIEnforced) {

        this.isDCRFAPIEnforced = isDCRFAPIEnforced;
    }

    public Boolean isClientAuthenticationRequired() {

        return clientAuthenticationRequired;
    }

    public void setClientAuthenticationRequired(Boolean clientAuthenticationRequired) {

        this.clientAuthenticationRequired = clientAuthenticationRequired;
    }

    public String getSsaJwks() {

        return ssaJwks;
    }

    public void setSsaJwks(String ssaJwks) {

        this.ssaJwks = ssaJwks;
    }
}
