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

package org.wso2.carbon.identity.oauth2.config.utils;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.config.exceptions.OAuth2OIDCConfigMgtClientException;
import org.wso2.carbon.identity.oauth2.config.exceptions.OAuth2OIDCConfigMgtServerException;
import org.wso2.carbon.identity.oauth2.config.models.IssuerUsageScopeConfig;
import org.wso2.carbon.identity.oauth2.config.models.UsageScope;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.organization.management.service.constant.OrganizationManagementConstants;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;

import static org.wso2.carbon.identity.core.util.IdentityCoreConstants.TENANT_NAME_FROM_CONTEXT;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OAuth20Endpoints.OAUTH2_TOKEN_EP_URL;

/**
 * Contains OAuth2 / OIDC configuration management related utility methods.
 */
public class OAuth2OIDCConfigUtils {

    private static final Log LOG = LogFactory.getLog(OAuth2OIDCConfigUtils.class);

    private OAuth2OIDCConfigUtils() {}

    /**
     * Returns the default issuer usage scope config for the given tenant domain.
     *
     * @param tenantDomain Tenant domain.
     * @return Default IssuerUsageScopeConfig.
     * @throws OAuth2OIDCConfigMgtServerException If an error occurs while building the issuer location.
     */
    public static IssuerUsageScopeConfig getDefaultIssuerUsageScopeConfig(String tenantDomain)
            throws OAuth2OIDCConfigMgtServerException {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Extracting default issuer usage scope config for tenant: " + tenantDomain);
        }
        String issuer = getIssuerLocation(tenantDomain);
        IssuerUsageScopeConfig issuerUsageScopeConfig = new IssuerUsageScopeConfig();
        issuerUsageScopeConfig.setIssuer(issuer);
        issuerUsageScopeConfig.setUsageScope(UsageScope.ALL_EXISTING_AND_FUTURE_ORGS);
        return issuerUsageScopeConfig;
    }

    /**
     * Returns the issuer location for the given tenant domain.
     *
     * @param tenantDomain Tenant domain whose issuer location is to be retrieved.
     * @return Issuer location.
     * @throws OAuth2OIDCConfigMgtServerException If an error occurs while building the issuer location.
     */
    public static String getIssuerLocation(String tenantDomain) throws OAuth2OIDCConfigMgtServerException {

        String prevThreadLocalTenant = null;
        String prevRootTenant = null;
        boolean tenantFlowStarted = false;
        String issuerLocation;
        try {
            /*
             Extracting tenant information from thread local properties and restoring it back at the end
             of the method from finally.
            */
            if (IdentityUtil.threadLocalProperties.get().get(TENANT_NAME_FROM_CONTEXT) != null) {
                prevThreadLocalTenant = IdentityUtil.threadLocalProperties.get().get(TENANT_NAME_FROM_CONTEXT)
                        .toString();
            }
            if (IdentityUtil.threadLocalProperties.get().get(OrganizationManagementConstants.ROOT_TENANT_DOMAIN)
                    != null) {
                prevRootTenant = IdentityUtil.threadLocalProperties.get().get(OrganizationManagementConstants.
                        ROOT_TENANT_DOMAIN).toString();
            }
            String orgId = OAuth2ServiceComponentHolder.getInstance().getOrganizationManager().
                    resolveOrganizationId(tenantDomain);
            if (OAuth2ServiceComponentHolder.getInstance().getOrganizationManager().isPrimaryOrganization(orgId)) {
                IdentityUtil.threadLocalProperties.get().put(TENANT_NAME_FROM_CONTEXT, tenantDomain);
                IdentityUtil.threadLocalProperties.get().put(OrganizationManagementConstants.ROOT_TENANT_DOMAIN, null);
                issuerLocation = OAuth2Util.getIssuerLocation(tenantDomain);
            } else {
                PrivilegedCarbonContext.startTenantFlow();
                String primaryOrganizationId = OAuth2ServiceComponentHolder.getInstance().getOrganizationManager().
                        getPrimaryOrganizationId(orgId);
                String primaryTenantDomain = OAuth2ServiceComponentHolder.getInstance().getOrganizationManager().
                        resolveTenantDomain(primaryOrganizationId);
                PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain(primaryTenantDomain);
                PrivilegedCarbonContext.getThreadLocalCarbonContext().setApplicationResidentOrganizationId(orgId);
                tenantFlowStarted = true;
                IdentityUtil.threadLocalProperties.get().put(TENANT_NAME_FROM_CONTEXT, primaryTenantDomain);
                IdentityUtil.threadLocalProperties.get().put(OrganizationManagementConstants.ROOT_TENANT_DOMAIN, null);
                issuerLocation = ServiceURLBuilder.create().addPath(OAUTH2_TOKEN_EP_URL).build().getAbsolutePublicURL();
            }
            return issuerLocation;
        } catch (IdentityOAuth2Exception | OrganizationManagementException | URLBuilderException e) {
            throw handleServerException(OAuth2OIDCConfigMgtErrorMessages.ERROR_CODE_OAUTH2_OIDC_CONFIG_ISSUER_BUILD,
                    e, tenantDomain);
        } finally {
            IdentityUtil.threadLocalProperties.get().put(TENANT_NAME_FROM_CONTEXT, prevThreadLocalTenant);
            IdentityUtil.threadLocalProperties.get().put(OrganizationManagementConstants.ROOT_TENANT_DOMAIN,
                        prevRootTenant);
            if (tenantFlowStarted) {
                PrivilegedCarbonContext.endTenantFlow();
            }
        }
    }

    /**
     * Handles server exceptions by creating an instance of OAuth2OIDCConfigMgtServerException.
     *
     * @param error The error message and code associated with the server exception.
     * @param e     The underlying cause of the server exception.
     * @param data  Additional data to be included in the error message.
     * @return An instance of OAuth2OIDCConfigMgtServerException.
     */
    public static OAuth2OIDCConfigMgtServerException handleServerException(OAuth2OIDCConfigMgtErrorMessages error,
                                                                           Throwable e, String... data) {

        return new OAuth2OIDCConfigMgtServerException(String.format(error.getDescription(), data), error.getCode(), e);
    }

    /**
     * Handles client exceptions by creating an instance of OAuth2OIDCConfigMgtClientException.
     *
     * @param error The error message and code associated with the client exception.
     * @param e     The underlying cause of the client exception.
     * @param data  Additional data to be included in the error message.
     * @return An instance of OAuth2OIDCConfigMgtClientException.
     */
    public static OAuth2OIDCConfigMgtClientException handleClientException(OAuth2OIDCConfigMgtErrorMessages error,
                                                                           Throwable e, String... data) {

        return new OAuth2OIDCConfigMgtClientException(String.format(error.getDescription(), data),
                error.getCode(), e);
    }
}
