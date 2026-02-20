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

package org.wso2.carbon.identity.oauth2.config.models;

import java.io.Serializable;

/**
 * Contains details related to an issuer, such as the organization ID and tenant domain it belongs to. This is used
 * when listing allowed issuers, to provide more information about the issuers to the users.
 */
public class IssuerDetails implements Serializable {

    private static final long serialVersionUID = 3847562910845672893L;

    private String issuer;
    private String issuerOrgId;
    private String issuerTenantDomain;

    public String getIssuer() {

        return issuer;
    }

    public void setIssuer(String issuer) {

        this.issuer = issuer;
    }

    public String getIssuerOrgId() {

        return issuerOrgId;
    }

    public void setIssuerOrgId(String issuerOrgId) {

        this.issuerOrgId = issuerOrgId;
    }

    public String getIssuerTenantDomain() {

        return issuerTenantDomain;
    }

    public void setIssuerTenantDomain(String issuerTenantDomain) {

        this.issuerTenantDomain = issuerTenantDomain;
    }

    @Override
    public int hashCode() {

        return java.util.Objects.hash(issuer, issuerOrgId, issuerTenantDomain);
    }

    @Override
    public boolean equals(Object obj) {

        if (this == obj) {
            return true;
        }
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }

        IssuerDetails issuerDetailsObject = (IssuerDetails) obj;
        return java.util.Objects.equals(issuer, issuerDetailsObject.issuer) &&
                java.util.Objects.equals(issuerOrgId, issuerDetailsObject.issuerOrgId) &&
                java.util.Objects.equals(issuerTenantDomain, issuerDetailsObject.issuerTenantDomain);
    }
}
