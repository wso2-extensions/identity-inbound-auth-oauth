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

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.ApplicationBasicInfo;
import org.wso2.carbon.identity.application.common.model.InboundAuthenticationRequestConfig;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.configuration.mgt.core.ConfigurationManager;
import org.wso2.carbon.identity.configuration.mgt.core.constant.ConfigurationConstants;
import org.wso2.carbon.identity.configuration.mgt.core.exception.ConfigurationManagementException;
import org.wso2.carbon.identity.configuration.mgt.core.model.Attribute;
import org.wso2.carbon.identity.configuration.mgt.core.model.Resource;
import org.wso2.carbon.identity.configuration.mgt.core.model.ResourceAdd;
import org.wso2.carbon.identity.core.util.LambdaExceptionUtils;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.config.exceptions.OAuth2OIDCConfigMgtException;
import org.wso2.carbon.identity.oauth2.config.exceptions.OAuth2OIDCConfigMgtServerException;
import org.wso2.carbon.identity.oauth2.config.models.IssuerDetails;
import org.wso2.carbon.identity.oauth2.config.models.IssuerUsageScopeConfig;
import org.wso2.carbon.identity.oauth2.config.models.OAuth2OIDCConfig;
import org.wso2.carbon.identity.oauth2.config.models.UsageScope;
import org.wso2.carbon.identity.oauth2.config.utils.OAuth2OIDCConfigConstants;
import org.wso2.carbon.identity.oauth2.config.utils.OAuth2OIDCConfigMgtErrorMessages;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.identity.organization.resource.hierarchy.traverse.service.OrgResourceResolverService;
import org.wso2.carbon.identity.organization.resource.hierarchy.traverse.service.strategy.MergeAllAggregationStrategy;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import static org.wso2.carbon.identity.oauth2.config.utils.OAuth2OIDCConfigUtils.getDefaultIssuerUsageScopeConfig;
import static org.wso2.carbon.identity.oauth2.config.utils.OAuth2OIDCConfigUtils.getIssuerLocation;
import static org.wso2.carbon.identity.oauth2.config.utils.OAuth2OIDCConfigUtils.handleClientException;
import static org.wso2.carbon.identity.oauth2.config.utils.OAuth2OIDCConfigUtils.handleServerException;

/**
 * Implementation of OAuth2OIDCConfigMgtService interface for OAuth2 / OIDC configuration management.
 */
public class OAuth2OIDCConfigMgtServiceImpl implements OAuth2OIDCConfigMgtService {

    private static final Log LOG = LogFactory.getLog(OAuth2OIDCConfigMgtServiceImpl.class);

    /**
     * Returns the OAuth2 / OIDC configurations of the tenant.
     *
     * @param tenantDomain Tenant domain to which the configurations belong to.
     * @return OAuth2OIDCConfig object containing the OAuth2 / OIDC configurations of the tenant.
     * @throws OAuth2OIDCConfigMgtException Error while retrieving the OAuth2 / OIDC configurations of the tenant.
     */
    @Override
    public OAuth2OIDCConfig getOAuth2OIDCConfigs(String tenantDomain) throws OAuth2OIDCConfigMgtException {

        OAuth2OIDCConfig oAuth2OIDCConfig = new OAuth2OIDCConfig();

        // Getting issuer usage Scope configuration.
        IssuerUsageScopeConfig issuerUsageScopeConfig;
        Resource resource;
        try {
            resource = getResource(OAuth2OIDCConfigConstants.ISSUER_USAGE_SCOPE_RESOURCE_TYPE_NAME,
                    OAuth2OIDCConfigConstants.TENANT_ISSUER_USAGE_SCOPE_RESOURCE_NAME, false);

            if (resource == null) {
                // Getting the default configurations.
                if (LOG.isDebugEnabled()) {
                    LOG.debug("No issuer usage scope configuration found for tenant: " + tenantDomain +
                            ". Loading default configurations as usage scope ALL_EXISTING_AND_FUTURE_ORGS.");
                }
                issuerUsageScopeConfig = getDefaultIssuerUsageScopeConfig(tenantDomain);
            } else {
                issuerUsageScopeConfig = parseResource(resource);
                issuerUsageScopeConfig.setIssuer(getIssuerLocation(tenantDomain));
            }
        } catch (ConfigurationManagementException e) {
            throw handleServerException(OAuth2OIDCConfigMgtErrorMessages.ERROR_CODE_OAUTH2_OIDC_CONFIG_RETRIEVE, e,
                    tenantDomain);
        }
        oAuth2OIDCConfig.setIssuerUsageScopeConfig(issuerUsageScopeConfig);

        return oAuth2OIDCConfig;
    }

    /**
     * Updates the OAuth2 / OIDC configurations of the tenant with the provided configurations.
     *
     * @param tenantDomain Tenant domain to which the configurations belong to.
     * @param oAuth2OIDCConfig OAuth2OIDCConfig object containing the updated OAuth2 / OIDC configurations.
     * @return OAuth2OIDCConfig object containing the updated OAuth2 / OIDC configurations of the tenant.
     * @throws OAuth2OIDCConfigMgtException Error while updating the OAuth2 / OIDC configurations of the tenant.
     */
    @Override
    public OAuth2OIDCConfig updateOAuth2OIDCConfigs(String tenantDomain, OAuth2OIDCConfig oAuth2OIDCConfig)
            throws OAuth2OIDCConfigMgtException {

        if (oAuth2OIDCConfig == null) {
            throw handleClientException(OAuth2OIDCConfigMgtErrorMessages.
                    ERROR_CODE_OAUTH2_OIDC_CONFIG_EMPTY_PATCH_OBJECT, null, tenantDomain);
        }

        if (oAuth2OIDCConfig.getIssuerUsageScopeConfig() != null) {
            Resource existingResource;
            try {
                existingResource = getResource(OAuth2OIDCConfigConstants.ISSUER_USAGE_SCOPE_RESOURCE_TYPE_NAME,
                        OAuth2OIDCConfigConstants.TENANT_ISSUER_USAGE_SCOPE_RESOURCE_NAME, false);
            } catch (ConfigurationManagementException e) {
                throw handleServerException(OAuth2OIDCConfigMgtErrorMessages.ERROR_CODE_OAUTH2_OIDC_CONFIG_RETRIEVE, e,
                        tenantDomain);
            }
            IssuerUsageScopeConfig issuerUsageScopeConfig = oAuth2OIDCConfig.getIssuerUsageScopeConfig();
            List<Attribute> attributes = Collections.singletonList(
                    new Attribute(OAuth2OIDCConfigConstants.ISSUER_USAGE_SCOPE_USAGE_SCOPE_ATTRIBUTE,
                            issuerUsageScopeConfig.getUsageScope().getValue())
            );
            if (UsageScope.NONE.equals(issuerUsageScopeConfig.getUsageScope())) {
                boolean isIssuerUsedInSubOrgs = false;
                String subOrgTenantDomain = null;
                try {
                    String orgId = OAuth2ServiceComponentHolder.getInstance().getOrganizationManager().
                            resolveOrganizationId(tenantDomain);
                    List<String> orgIdList = OAuth2ServiceComponentHolder.getInstance().getOrganizationManager()
                            .getChildOrganizationsIds(orgId, true);
                    String username = PrivilegedCarbonContext.getThreadLocalCarbonContext().getUsername();
                    if (!orgIdList.isEmpty()) {
                        outerLoop:
                        for (String subOrgId : orgIdList) {
                            subOrgTenantDomain = OAuth2ServiceComponentHolder.getInstance()
                                    .getOrganizationManager().resolveTenantDomain(subOrgId);
                            int appCount = OAuth2ServiceComponentHolder.getApplicationMgtService().
                                    getCountOfApplications(subOrgTenantDomain, username, null, true);
                            int limit = 100;
                            int offset = 0;

                            while (offset < appCount) {
                                ApplicationBasicInfo[] orgAppBasicInfoList = OAuth2ServiceComponentHolder.
                                        getApplicationMgtService().getApplicationBasicInfo(subOrgTenantDomain,
                                                username, null, offset, limit, Boolean.TRUE);
                                if (orgAppBasicInfoList != null) {
                                    for (ApplicationBasicInfo appBasicInfo : orgAppBasicInfoList) {
                                        ServiceProvider applicationBasicInfo = OAuth2ServiceComponentHolder.
                                                getApplicationMgtService().getApplicationByResourceId(
                                                        appBasicInfo.getUuid(), subOrgTenantDomain);
                                        if (applicationBasicInfo.getInboundAuthenticationConfig() != null) {
                                            for (int i = 0; i < applicationBasicInfo.getInboundAuthenticationConfig().
                                                    getInboundAuthenticationRequestConfigs().length; i++) {
                                                InboundAuthenticationRequestConfig inboundAuthConfig =
                                                        applicationBasicInfo.getInboundAuthenticationConfig().
                                                        getInboundAuthenticationRequestConfigs()[i];
                                                if (!"oauth2".equals(inboundAuthConfig.getInboundAuthType())) {
                                                    continue;
                                                }
                                                OAuthAppDO oauthAppDO = OAuth2Util.getAppInformationByClientId(
                                                        inboundAuthConfig.getInboundAuthKey(),
                                                        subOrgTenantDomain);
                                                if (oauthAppDO != null) {
                                                    String appIssuerOrg = oauthAppDO.getIssuerOrg();
                                                    if (appIssuerOrg == null ||
                                                            StringUtils.equals(appIssuerOrg, orgId)) {
                                                        isIssuerUsedInSubOrgs = true;
                                                        break outerLoop;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                offset += limit;
                            }
                        }
                    }
                } catch (OrganizationManagementException e) {
                    throw handleServerException(OAuth2OIDCConfigMgtErrorMessages.
                            ERROR_CODE_OAUTH2_OIDC_CONFIG_ORG_RESOLVE, e, tenantDomain);
                } catch (IdentityApplicationManagementException e) {
                    throw handleServerException(OAuth2OIDCConfigMgtErrorMessages.
                                    ERROR_CODE_OAUTH2_OIDC_CONFIG_APP_RETRIEVE, e, subOrgTenantDomain);
                } catch (IdentityOAuth2Exception | InvalidOAuthClientException e) {
                    throw handleServerException(OAuth2OIDCConfigMgtErrorMessages.
                            ERROR_CODE_OAUTH2_OIDC_CONFIG_APP_INFO_RETRIEVE, e, StringUtils.EMPTY);
                }

                if (isIssuerUsedInSubOrgs) {
                    throw handleClientException(OAuth2OIDCConfigMgtErrorMessages.
                            ERROR_CODE_OAUTH2_OIDC_CONFIG_ISSUER_USAGE_SCOPE_CHANGE_REJECT, null, tenantDomain);
                } else {
                    if (existingResource == null) {
                        addConfigurationResource(tenantDomain, attributes);
                    } else {
                        replaceConfigurationResource(tenantDomain, attributes);
                    }
                }
            } else {
                if (existingResource == null) {
                    addConfigurationResource(tenantDomain, attributes);
                } else {
                    replaceConfigurationResource(tenantDomain, attributes);
                }
            }
        }

        return getOAuth2OIDCConfigs(tenantDomain);
    }

    private void addConfigurationResource(String tenantDomain, List<Attribute> attributes)
            throws OAuth2OIDCConfigMgtServerException {
        if (LOG.isDebugEnabled()) {
            LOG.debug("No existing issuer usage scope configuration found for tenant: "
                    + tenantDomain + ". Patching the null resource with a new resource.");
        }
        ResourceAdd resourceAdd = new ResourceAdd();
        resourceAdd.setName(OAuth2OIDCConfigConstants.TENANT_ISSUER_USAGE_SCOPE_RESOURCE_NAME);
        resourceAdd.setAttributes(attributes);
        try {
            getConfigurationManager().addResource(OAuth2OIDCConfigConstants.
                    ISSUER_USAGE_SCOPE_RESOURCE_TYPE_NAME, resourceAdd);
        } catch (ConfigurationManagementException e) {
            throw handleServerException(OAuth2OIDCConfigMgtErrorMessages.
                    ERROR_CODE_OAUTH2_OIDC_CONFIG_ISSUER_USAGE_SCOPE_ADD, e, tenantDomain);
        }
    }

    private void replaceConfigurationResource(String tenantDomain, List<Attribute> attributes)
            throws OAuth2OIDCConfigMgtServerException {

        ResourceAdd resourceAdd = new ResourceAdd();
        resourceAdd.setName(OAuth2OIDCConfigConstants.TENANT_ISSUER_USAGE_SCOPE_RESOURCE_NAME);
        resourceAdd.setAttributes(attributes);
        try {
            getConfigurationManager().replaceResource(OAuth2OIDCConfigConstants.
                    ISSUER_USAGE_SCOPE_RESOURCE_TYPE_NAME, resourceAdd);
        } catch (ConfigurationManagementException e) {
            throw handleServerException(OAuth2OIDCConfigMgtErrorMessages.
                    ERROR_CODE_OAUTH2_OIDC_CONFIG_ISSUER_USAGE_SCOPE_UPDATE, e, tenantDomain);
        }
    }

    /**
     * Returns the list of allowed issuer locations for the tenant based on the issuer usage scope defined in the
     * ancestor tenants / organizations of the current tenant. The tenant / organization is resolved from the
     * current carbon context.
     *
     * @return List of allowed issuer locations for the tenant.
     * @throws OAuth2OIDCConfigMgtException Error while retrieving the allowed issuer locations for the tenant.
     */
    @Override
    public List<String> getAllowedIssuers() throws OAuth2OIDCConfigMgtException {

        OrgResourceResolverService orgResourceResolverService = OAuth2ServiceComponentHolder.getInstance()
                .getOrgResourceResolverService();
        String tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        try {
            String orgId = OAuth2ServiceComponentHolder.getInstance().getOrganizationManager().
                    resolveOrganizationId(tenantDomain);
            if (OAuth2ServiceComponentHolder.getInstance().getOrganizationManager().isPrimaryOrganization(orgId)) {
                return null;
            }
            return orgResourceResolverService.getResourcesFromOrgHierarchy(orgId,
                    LambdaExceptionUtils.rethrowFunction(this::getAllowedIssuerForOrg),
                    new MergeAllAggregationStrategy<>(this::mergeIssuersInHierarchy));
        } catch (Exception e) {
            throw handleServerException(OAuth2OIDCConfigMgtErrorMessages.ERROR_CODE_OAUTH2_OIDC_CONFIG_RETRIEVE, e,
                    tenantDomain);
        }
    }

    /**
     * Returns the list of allowed issuer details for the tenant based on the issuer usage scope defined in the
     * ancestor tenants / organizations of the current tenant. The tenant / organization is resolved from the
     * current carbon context.
     *
     * @return List of allowed issuer details for the tenant.
     * @throws OAuth2OIDCConfigMgtException Error while retrieving the allowed issuer details for the tenant.
     */
    @Override
    public List<IssuerDetails> getAllowedIssuerDetails() throws OAuth2OIDCConfigMgtException {

        OrgResourceResolverService orgResourceResolverService = OAuth2ServiceComponentHolder.getInstance()
                .getOrgResourceResolverService();
        String tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        String appResidentOrgId = PrivilegedCarbonContext.getThreadLocalCarbonContext()
                .getApplicationResidentOrganizationId();
        try {
            if (StringUtils.isNotEmpty(appResidentOrgId)) {
                tenantDomain = OAuth2ServiceComponentHolder.getInstance().getOrganizationManager()
                        .resolveTenantDomain(appResidentOrgId);
            }

            String orgId = OAuth2ServiceComponentHolder.getInstance().getOrganizationManager().
                    resolveOrganizationId(tenantDomain);
            if (OAuth2ServiceComponentHolder.getInstance().getOrganizationManager().isPrimaryOrganization(orgId)) {
                return null;
            }
            return orgResourceResolverService.getResourcesFromOrgHierarchy(orgId,
                    LambdaExceptionUtils.rethrowFunction(this::getAllowedIssuerDetailsForOrg),
                    new MergeAllAggregationStrategy<>(this::mergeIssuersDetailsInHierarchy));
        } catch (Exception e) {
            throw handleServerException(OAuth2OIDCConfigMgtErrorMessages.ERROR_CODE_OAUTH2_OIDC_CONFIG_RETRIEVE, e,
                    tenantDomain);
        }
    }

    private Optional<List<String>> getAllowedIssuerForOrg(String orgId) throws OAuth2OIDCConfigMgtServerException {

        try {
            String tenantDomain = OAuth2ServiceComponentHolder.getInstance().getOrganizationManager().
                    resolveTenantDomain(orgId);
            int tenantId = OAuth2Util.getTenantId(tenantDomain);

            PrivilegedCarbonContext.startTenantFlow();
            PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantId(tenantId);

            IssuerUsageScopeConfig issuerUsageScopeConfig;
            Resource resource = getResource(OAuth2OIDCConfigConstants.ISSUER_USAGE_SCOPE_RESOURCE_TYPE_NAME,
                    OAuth2OIDCConfigConstants.TENANT_ISSUER_USAGE_SCOPE_RESOURCE_NAME, false);

            if (resource == null) {
                // Getting the default configurations.
                if (LOG.isDebugEnabled()) {
                    LOG.debug("No issuer usage scope configuration found for tenant: " + tenantDomain +
                            ". Loading default configurations as usage scope ALL_EXISTING_AND_FUTURE_ORGS.");
                }
                issuerUsageScopeConfig = getDefaultIssuerUsageScopeConfig(tenantDomain);
            } else {
                issuerUsageScopeConfig = parseResource(resource);
                issuerUsageScopeConfig.setIssuer(getIssuerLocation(tenantDomain));
            }
            if (!UsageScope.NONE.equals(issuerUsageScopeConfig.getUsageScope())) {
                return Optional.of(Collections.singletonList(issuerUsageScopeConfig.getIssuer()));
            }
            return Optional.empty();
        } catch (OrganizationManagementException | IdentityOAuth2Exception | ConfigurationManagementException |
                 OAuth2OIDCConfigMgtServerException e) {
            throw handleServerException(OAuth2OIDCConfigMgtErrorMessages.
                    ERROR_CODE_OAUTH2_OIDC_CONFIG_ISSUER_USAGE_SCOPE_GET, e, orgId);
        } finally {
            PrivilegedCarbonContext.endTenantFlow();
        }
    }

    private Optional<List<IssuerDetails>> getAllowedIssuerDetailsForOrg(String orgId) throws
            OAuth2OIDCConfigMgtServerException {

        try {
            String tenantDomain = OAuth2ServiceComponentHolder.getInstance().getOrganizationManager().
                    resolveTenantDomain(orgId);
            int tenantId = OAuth2Util.getTenantId(tenantDomain);

            PrivilegedCarbonContext.startTenantFlow();
            PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantId(tenantId);

            IssuerUsageScopeConfig issuerUsageScopeConfig;
            Resource resource = getResource(OAuth2OIDCConfigConstants.ISSUER_USAGE_SCOPE_RESOURCE_TYPE_NAME,
                    OAuth2OIDCConfigConstants.TENANT_ISSUER_USAGE_SCOPE_RESOURCE_NAME, false);

            if (resource == null) {
                // Getting the default configurations.
                if (LOG.isDebugEnabled()) {
                    LOG.debug("No issuer usage scope configuration found for tenant: " + tenantDomain +
                            ". Loading default configurations as usage scope ALL_EXISTING_AND_FUTURE_ORGS.");
                }
                issuerUsageScopeConfig = getDefaultIssuerUsageScopeConfig(tenantDomain);
            } else {
                issuerUsageScopeConfig = parseResource(resource);
                issuerUsageScopeConfig.setIssuer(getIssuerLocation(tenantDomain));
            }
            if (!UsageScope.NONE.equals(issuerUsageScopeConfig.getUsageScope())) {
                IssuerDetails issuerDetails = new IssuerDetails();
                issuerDetails.setIssuer(issuerUsageScopeConfig.getIssuer());
                issuerDetails.setIssuerOrgId(orgId);
                issuerDetails.setIssuerTenantDomain(tenantDomain);
                return Optional.of(Collections.singletonList(issuerDetails));
            }
            return Optional.empty();
        } catch (OrganizationManagementException | IdentityOAuth2Exception | ConfigurationManagementException |
                 OAuth2OIDCConfigMgtServerException e) {
            throw handleServerException(OAuth2OIDCConfigMgtErrorMessages.
                    ERROR_CODE_OAUTH2_OIDC_CONFIG_ISSUER_USAGE_SCOPE_GET, e, orgId);
        } finally {
            PrivilegedCarbonContext.endTenantFlow();
        }
    }

    private List<String> mergeIssuersInHierarchy(List<String> existingIssuers, List<String> currentIssuers) {

        java.util.Set<String> mergedIssuersSet = new java.util.LinkedHashSet<>();
        if (existingIssuers != null) {
            mergedIssuersSet.addAll(existingIssuers);
        }
        if (currentIssuers != null) {
            mergedIssuersSet.addAll(currentIssuers);
        }
        return new java.util.ArrayList<>(mergedIssuersSet);
    }

    private List<IssuerDetails> mergeIssuersDetailsInHierarchy(List<IssuerDetails> existingIssuers,
                                                               List<IssuerDetails> currentIssuers) {

        java.util.Set<IssuerDetails> mergedIssuersSet = new java.util.LinkedHashSet<>();
        if (existingIssuers != null) {
            mergedIssuersSet.addAll(existingIssuers);
        }
        if (currentIssuers != null) {
            mergedIssuersSet.addAll(currentIssuers);
        }
        return new java.util.ArrayList<>(mergedIssuersSet);
    }

    private ConfigurationManager getConfigurationManager() {

        return OAuth2ServiceComponentHolder.getInstance().getConfigurationManager();
    }

    private Resource getResource(String resourceTypeName, String resourceName, boolean inherited)
            throws ConfigurationManagementException {

        try {
            if (getConfigurationManager() != null) {
                return getConfigurationManager().getResource(resourceTypeName, resourceName, inherited);
            }
            return null;
        } catch (ConfigurationManagementException e) {
            if (ConfigurationConstants.ErrorMessages.ERROR_CODE_RESOURCE_DOES_NOT_EXISTS.getCode().
                    equals(e.getErrorCode())) {
                return null;
            } else {
                throw e;
            }
        }
    }

    private IssuerUsageScopeConfig parseResource(Resource resource) throws OAuth2OIDCConfigMgtServerException {

        IssuerUsageScopeConfig issuerUsageScopeConfig = new IssuerUsageScopeConfig();
        if (resource.isHasAttribute()) {
            List<Attribute> attributes = resource.getAttributes();
            Map<String, String> attributeMap = getAttributeMap(attributes);
            String usageScopeValue = attributeMap.get(OAuth2OIDCConfigConstants.
                    ISSUER_USAGE_SCOPE_USAGE_SCOPE_ATTRIBUTE);
            if (usageScopeValue != null) {
                issuerUsageScopeConfig.setUsageScope(UsageScope.fromValue(usageScopeValue));
            }
        }
        return issuerUsageScopeConfig;
    }

    private Map<String, String> getAttributeMap(List<Attribute> attributes) {

        if (CollectionUtils.isNotEmpty(attributes)) {
            return attributes.stream().collect(Collectors.toMap(Attribute::getKey, Attribute::getValue));
        }
        return Collections.emptyMap();
    }
}
