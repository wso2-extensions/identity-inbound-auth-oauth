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

package org.wso2.carbon.identity.oauth.dcr.util;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.base.IdentityRuntimeException;
import org.wso2.carbon.identity.configuration.mgt.core.ConfigurationManager;
import org.wso2.carbon.identity.configuration.mgt.core.exception.ConfigurationManagementException;
import org.wso2.carbon.identity.configuration.mgt.core.model.Attribute;
import org.wso2.carbon.identity.configuration.mgt.core.model.Resource;
import org.wso2.carbon.identity.configuration.mgt.core.model.ResourceAdd;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.dcr.DCRMConstants;
import org.wso2.carbon.identity.oauth.dcr.exception.DCRMClientException;
import org.wso2.carbon.identity.oauth.dcr.exception.DCRMServerException;
import org.wso2.carbon.identity.oauth.dcr.internal.DCRDataHolder;
import org.wso2.carbon.identity.oauth.dcr.model.DCRConfiguration;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.wso2.carbon.identity.configuration.mgt.core.constant.ConfigurationConstants.ErrorMessages.ERROR_CODE_RESOURCE_DOES_NOT_EXISTS;
import static org.wso2.carbon.identity.configuration.mgt.core.constant.ConfigurationConstants.ErrorMessages.ERROR_CODE_RESOURCE_TYPE_DOES_NOT_EXISTS;
import static org.wso2.carbon.identity.oauth.dcr.DCRMConstants.CLIENT_AUTHENTICATION_REQUIRED;
import static org.wso2.carbon.identity.oauth.dcr.DCRMConstants.DCRConfigErrorMessage.ERROR_CODE_DCR_CONFIGURATION_RETRIEVE;
import static org.wso2.carbon.identity.oauth.dcr.DCRMConstants.DCR_CONFIG_RESOURCE_NAME;
import static org.wso2.carbon.identity.oauth.dcr.DCRMConstants.DCR_CONFIG_RESOURCE_TYPE_NAME;
import static org.wso2.carbon.identity.oauth.dcr.DCRMConstants.ENABLE_FAPI_ENFORCEMENT;
import static org.wso2.carbon.identity.oauth.dcr.DCRMConstants.MANDATE_SSA;
import static org.wso2.carbon.identity.oauth.dcr.DCRMConstants.SSA_JWKS;
import static org.wso2.carbon.identity.oauth.dcr.util.DCRConfigErrorUtils.handleClientException;
import static org.wso2.carbon.identity.oauth.dcr.util.DCRConfigErrorUtils.handleServerException;


/**
 * Util class for DCR configurations and DCR resource related operations.
 */
public class DCRConfigUtils {

    private DCRConfigUtils() { }

    /**
     * Validate the tenant domain.
     *
     * @param tenantDomain The tenant domain.
     * @throws DCRMClientException If the tenant domain is invalid.
     */
    public static void validateTenantDomain(String tenantDomain)
            throws DCRMClientException {

        try {
            IdentityTenantUtil.getTenantId(tenantDomain);
        } catch (IdentityRuntimeException e) {
            throw handleClientException(DCRMConstants.DCRConfigErrorMessage.ERROR_CODE_INVALID_TENANT_DOMAIN, e,
                    tenantDomain);
        }
    }

    /**
     * Persist the DCRConfiguration object.
     *
     * @param dcrConfiguration The DCRConfiguration object.
     */
    public static void setDCRConfigurationByTenantDomain(DCRConfiguration dcrConfiguration)
            throws DCRMServerException {

        try {
            ResourceAdd resourceAdd = parseConfig(dcrConfiguration);
            getConfigurationManager().replaceResource(DCR_CONFIG_RESOURCE_TYPE_NAME, resourceAdd);
        } catch (ConfigurationManagementException e) {
            throw handleServerException(ERROR_CODE_DCR_CONFIGURATION_RETRIEVE, e);
        }
    }

    public static ConfigurationManager getConfigurationManager() {

        return DCRDataHolder.getInstance().getConfigurationManager();
    }

    /**
     * Get DCR configuration by tenant domain.
     * If there is a resource available for the tenant with the given resource type and resource name,
     * it will override the server configuration.
     * @return DCRConfiguration.
     * @throws DCRMServerException DCRMServerException.
     */
    public static DCRConfiguration getDCRConfiguration() throws DCRMServerException {

        try {
//            tenantDomain is resolved inside getResource() method.
            Resource resource = getResource(DCR_CONFIG_RESOURCE_TYPE_NAME, DCR_CONFIG_RESOURCE_NAME);
            DCRConfiguration dcrConfiguration = getDCRServerConfiguration();
            if (resource != null) {
                overrideConfigsWithResource(resource, dcrConfiguration);
            }

            return dcrConfiguration;
        } catch (ConfigurationManagementException e) {
            throw handleServerException(ERROR_CODE_DCR_CONFIGURATION_RETRIEVE, e);
        }
    }

    /**
     * Configuration Management API returns a ConfigurationManagementException with the error code CONFIGM_00017 when
     * resource is not found. This method wraps the original method and returns null if the resource is not found.
     *
     * @param resourceTypeName Resource type name.
     * @param resourceName     Resource name.
     * @return Retrieved resource from the configuration store. Returns {@code null} if the resource is not found.
     * @throws ConfigurationManagementException exception
     */
    private static Resource getResource(String resourceTypeName, String resourceName)
            throws ConfigurationManagementException {

        try {

            return getConfigurationManager().getResource(resourceTypeName, resourceName);
        } catch (ConfigurationManagementException e) {
            if (ERROR_CODE_RESOURCE_DOES_NOT_EXISTS.getCode().equals(e.getErrorCode()) ||
                    ERROR_CODE_RESOURCE_TYPE_DOES_NOT_EXISTS.getCode().equals(e.getErrorCode())) {

                return null;
            } else {
                throw e;
            }
        }
    }

    /**
     * Get the DCR configuration from the server configuration.
     *
     * @return DCRConfiguration The DCR configuration.
     */
    private static DCRConfiguration getDCRServerConfiguration() throws DCRMServerException {

        DCRConfiguration dcrConfiguration = new DCRConfiguration();

        String enableDCRFapiValue = IdentityUtil.getProperty(OAuthConstants.ENABLE_DCR_FAPI_ENFORCEMENT);
        Boolean enableDCRFapi = enableDCRFapiValue != null ? Boolean.parseBoolean(enableDCRFapiValue) : null;

        String clientAuthenticationRequiredValue = IdentityUtil.getProperty(
                OAuthConstants.DCR_CLIENT_AUTHENTICATION_REQUIRED);
        Boolean clientAuthenticationRequired = clientAuthenticationRequiredValue != null ?
                Boolean.parseBoolean(clientAuthenticationRequiredValue) : null;

        String ssaJwks = IdentityUtil.getProperty(OAuthConstants.DCR_SSA_VALIDATION_JWKS);
        String mandateSSA = IdentityUtil.getProperty(OAuthConstants.DCR_MANDATE_SSA);

        dcrConfiguration.setFAPIEnforced(enableDCRFapi);
        dcrConfiguration.setClientAuthenticationRequired(clientAuthenticationRequired);
        dcrConfiguration.setSsaJwks(ssaJwks);

        dcrConfiguration.setMandateSSA(mandateSSA);

        return dcrConfiguration;
    }

    /**
     * Override the server configuration with resource values.
     *
     * @param resource Resource
     */
    public static void overrideConfigsWithResource(Resource resource, DCRConfiguration dcrConfiguration)
            throws DCRMServerException {

        if (resource.isHasAttribute()) {
            List<Attribute> attributes = resource.getAttributes();
            Map<String, String> attributeMap = getAttributeMap(attributes);

            String enableDCRFapiValue = attributeMap.get(ENABLE_FAPI_ENFORCEMENT);
            Boolean enableDCRFapi = enableDCRFapiValue != null ? Boolean.parseBoolean(enableDCRFapiValue) : null;

            String clientAuthenticationRequiredValue = attributeMap.get(CLIENT_AUTHENTICATION_REQUIRED);
            Boolean clientAuthenticationRequired = clientAuthenticationRequiredValue != null ?
                    Boolean.parseBoolean(clientAuthenticationRequiredValue) : null;

            String ssaJwks = attributeMap.get(SSA_JWKS);
            String mandateSSA = attributeMap.get(MANDATE_SSA);

            if (enableDCRFapi != null) {
                dcrConfiguration.setFAPIEnforced(enableDCRFapi);
            }
            if (clientAuthenticationRequired != null) {
                dcrConfiguration.setClientAuthenticationRequired(clientAuthenticationRequired);
            }
            if (ssaJwks != null) {
                dcrConfiguration.setSsaJwks(ssaJwks);
            }
            if (mandateSSA != null) {
                dcrConfiguration.setMandateSSA(mandateSSA);
            }
        }

    }

    private static Map<String, String> getAttributeMap(List<Attribute> attributes) {

        if (CollectionUtils.isNotEmpty(attributes)) {
            return attributes.stream().collect(Collectors.toMap(Attribute::getKey, Attribute::getValue));
        }

        return Collections.emptyMap();
    }

    /**
     * Parse DCRConfiguration to Resource instance.
     *
     * @param dcrConfiguration Configuration Instance.
     * @return ResourceAdd Resource instance.
     */
    public static ResourceAdd parseConfig(DCRConfiguration dcrConfiguration) {

        ResourceAdd resourceAdd = new ResourceAdd();
        resourceAdd.setName(DCR_CONFIG_RESOURCE_NAME);
        List<Attribute> attributes = new ArrayList<>();

        String isFAPIEnforced;
        String isClientAuthenticationRequired;
        String ssaJwks;
        String mandateSSA;

        isFAPIEnforced = dcrConfiguration.isFAPIEnforced() != null ?
                String.valueOf(dcrConfiguration.isFAPIEnforced()) : null;
        isClientAuthenticationRequired = dcrConfiguration.isClientAuthenticationRequired() != null ?
                String.valueOf(dcrConfiguration.isClientAuthenticationRequired()) : null;
        ssaJwks = dcrConfiguration.getSsaJwks();
        mandateSSA = dcrConfiguration.getMandateSSA();

        addAttribute(attributes, ENABLE_FAPI_ENFORCEMENT, isFAPIEnforced);
        addAttribute(attributes, CLIENT_AUTHENTICATION_REQUIRED, isClientAuthenticationRequired);
        addAttribute(attributes, SSA_JWKS, ssaJwks);
        addAttribute(attributes, MANDATE_SSA, mandateSSA);

        resourceAdd.setAttributes(attributes);

        return resourceAdd;
    }

    private static void addAttribute(List<Attribute> attributeList, String key, String value) {

        if (StringUtils.isNotBlank(value)) {
            Attribute attribute = new Attribute();
            attribute.setKey(key);
            attribute.setValue(value);
            attributeList.add(attribute);
        }
    }
}
