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

package org.wso2.carbon.identity.oauth2.config.services;

import org.wso2.carbon.identity.oauth2.config.exceptions.OAuth2OIDCConfigOrgUsageScopeMgtException;
import org.wso2.carbon.identity.oauth2.config.models.IssuerDetails;
import org.wso2.carbon.identity.oauth2.config.models.IssuerUsageScopeConfig;

import java.util.List;

/**
 * Service interface for OAuth2 / OIDC configuration management.
 */
public interface OAuth2OIDCConfigOrgUsageScopeMgtService {

    /**
     * Returns the issuer usage scope of the tenant.
     *
     * @param tenantDomain Tenant domain to which the issuer usage scope belongs to.
     * @return IssuerUsageScopeConfig object containing the usage scope of the issuer configuration.
     * @throws OAuth2OIDCConfigOrgUsageScopeMgtException Error while retrieving the issuer usage scope config of
     * the tenant.
     */
    IssuerUsageScopeConfig getIssuerUsageScopeConfig(String tenantDomain)
            throws OAuth2OIDCConfigOrgUsageScopeMgtException;

    /**
     * Updates the issuer usage scope configurations of the tenant with the provided configurations.
     *
     * @param tenantDomain Tenant domain to which the configurations belong to.
     * @param issuerUsageScopeConfig OAuth2OIDCConfig object containing the updated issuer usage scope configurations.
     * @return IssuerUsageScopeConfig object containing the updated issuer usage scope configurations of the tenant.
     * @throws OAuth2OIDCConfigOrgUsageScopeMgtException Error while updating the issuer usage scope configurations
     * of the tenant.
     */
    IssuerUsageScopeConfig updateIssuerUsageScopeConfig(String tenantDomain,
                                                        IssuerUsageScopeConfig issuerUsageScopeConfig)
            throws OAuth2OIDCConfigOrgUsageScopeMgtException;

    /**
     * Returns the list of allowed issuer locations for the tenant based on the issuer usage scope defined in the
     * ancestor tenants / organizations of the current tenant. The tenant / organization is resolved from the
     * current carbon context.
     *
     * @return List of allowed issuer locations for the tenant.
     * @throws OAuth2OIDCConfigOrgUsageScopeMgtException Error while retrieving the allowed issuer locations for
     * the tenant.
     */
    List<String> getAllowedIssuers() throws OAuth2OIDCConfigOrgUsageScopeMgtException;

    /**
     * Returns the list of allowed issuer details for the tenant based on the issuer usage scope defined in the
     * ancestor tenants / organizations of the current tenant. The tenant / organization is resolved from the
     * current carbon context.
     *
     * @return List of allowed issuer details for the tenant.
     * @throws OAuth2OIDCConfigOrgUsageScopeMgtException Error while retrieving the allowed issuer details
     * for the tenant.
     */
    List<IssuerDetails> getAllowedIssuerDetails() throws OAuth2OIDCConfigOrgUsageScopeMgtException;
}
