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

package org.wso2.carbon.identity.oauth.dcr;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.configuration.mgt.core.ConfigurationManager;
import org.wso2.carbon.identity.configuration.mgt.core.exception.ConfigurationManagementException;
import org.wso2.carbon.identity.configuration.mgt.core.model.Attribute;
import org.wso2.carbon.identity.configuration.mgt.core.model.Resource;
import org.wso2.carbon.identity.configuration.mgt.core.model.ResourceAdd;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
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
 * Service layer implementation for managing the DCR configurations of a tenant.
 */
public class DCRConfigurationMgtServiceImpl implements DCRConfigurationMgtService {

    /**
     * {@inheritDoc}
     */
    @Override
    public DCRConfiguration getDCRConfiguration() throws DCRMServerException {

        try {
            // tenantDomain is resolved inside getResource() method.
            Resource resource = getResource(DCR_CONFIG_RESOURCE_TYPE_NAME, DCR_CONFIG_RESOURCE_NAME);
            DCRConfiguration dcrConfiguration = getDCRServerConfiguration();
            if (resource != null) {
                overrideDCRServerConfigsWithDCRResourceConfig(resource, dcrConfiguration);
            }

            return dcrConfiguration;
        } catch (ConfigurationManagementException e) {
            throw handleServerException(ERROR_CODE_DCR_CONFIGURATION_RETRIEVE, e);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setDCRConfiguration(DCRConfiguration dcrConfiguration)
            throws DCRMServerException, DCRMClientException {

        try {
            validateMandateSSA(dcrConfiguration);
            ResourceAdd resourceAdd = parseConfig(dcrConfiguration);
            getConfigurationManager().replaceResource(DCR_CONFIG_RESOURCE_TYPE_NAME, resourceAdd);
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
    private Resource getResource(String resourceTypeName, String resourceName)
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

    private ConfigurationManager getConfigurationManager() {

        return DCRDataHolder.getInstance().getConfigurationManager();
    }

    /**
     * Get the DCR configuration from the server configuration.
     *
     * @return DCRConfiguration The DCR configuration.
     */
    private DCRConfiguration getDCRServerConfiguration() {

        DCRConfiguration dcrConfiguration = new DCRConfiguration();

        Boolean enableFapiEnforcement = getBooleanFromString(
                IdentityUtil.getProperty(OAuthConstants.ENABLE_DCR_FAPI_ENFORCEMENT));
        Boolean authenticationRequired = getBooleanFromString(IdentityUtil.getProperty(
                OAuthConstants.DCR_CLIENT_AUTHENTICATION_REQUIRED));
        Boolean mandateSSA = getBooleanFromString(IdentityUtil.getProperty(OAuthConstants.DCR_MANDATE_SSA));
        String ssaJwks = IdentityUtil.getProperty(OAuthConstants.DCR_SSA_VALIDATION_JWKS);

        dcrConfiguration.setEnableFapiEnforcement(enableFapiEnforcement);
        dcrConfiguration.setAuthenticationRequired(authenticationRequired);
        dcrConfiguration.setMandateSSA(mandateSSA);
        dcrConfiguration.setSsaJwks(ssaJwks);

        return dcrConfiguration;
    }

    /**
     * Converts string to Boolean and prevent null values being converted to false.
     *
     * @param value String value.
     * @return Boolean value.
     */
    private Boolean getBooleanFromString(String value) {

        return value != null ? Boolean.parseBoolean(value) : null;
    }

    /**
     * Override the server configuration with resource values.
     *
     * @param resource Resource
     */
    private void overrideDCRServerConfigsWithDCRResourceConfig(Resource resource,
                                                                      DCRConfiguration dcrConfiguration) {

        if (resource.isHasAttribute()) {
            List<Attribute> attributes = resource.getAttributes();
            Map<String, String> attributeMap = getAttributeMap(attributes);

            Boolean enableFapiEnforcement = getBooleanFromString(attributeMap.get(ENABLE_FAPI_ENFORCEMENT));
            Boolean authenticationRequired = getBooleanFromString(
                    attributeMap.get(CLIENT_AUTHENTICATION_REQUIRED));
            Boolean mandateSSA = getBooleanFromString(attributeMap.get(MANDATE_SSA));
            String ssaJwks = attributeMap.get(SSA_JWKS);

            if (enableFapiEnforcement != null) {
                dcrConfiguration.setEnableFapiEnforcement(enableFapiEnforcement);
            }
            if (authenticationRequired != null) {
                dcrConfiguration.setAuthenticationRequired(authenticationRequired);
            }
            if (ssaJwks != null) {
                dcrConfiguration.setSsaJwks(ssaJwks);
            }
            if (mandateSSA != null) {
                dcrConfiguration.setMandateSSA(mandateSSA);
            }
        }
    }

    private Map<String, String> getAttributeMap(List<Attribute> attributes) {

        if (CollectionUtils.isNotEmpty(attributes)) {
            return attributes.stream().collect(Collectors.toMap(Attribute::getKey, Attribute::getValue));
        }

        return Collections.emptyMap();
    }

    private void validateMandateSSA (DCRConfiguration dcrConfiguration) throws DCRMClientException {

        if (Boolean.TRUE.equals(dcrConfiguration.getMandateSSA()) &&
                StringUtils.isBlank(dcrConfiguration.getSsaJwks())) {
            // if mandateSSA is True, ssaJwks should be provided.
            throw handleClientException(DCRMConstants.DCRConfigErrorMessage.ERROR_CODE_SSA_JWKS_REQUIRED);
        }
    }

    /**
     * Parse DCRConfiguration to Resource instance.
     *
     * @param dcrConfiguration Configuration Instance.
     * @return ResourceAdd Resource instance.
     */
    private ResourceAdd parseConfig(DCRConfiguration dcrConfiguration) {

        ResourceAdd resourceAdd = new ResourceAdd();
        resourceAdd.setName(DCR_CONFIG_RESOURCE_NAME);
        List<Attribute> attributes = new ArrayList<>();

        String enableFapiEnforcement;
        String authenticationRequired;
        String ssaJwks;
        String mandateSSA;

        enableFapiEnforcement = dcrConfiguration.getEnableFapiEnforcement() != null ?
                String.valueOf(dcrConfiguration.getEnableFapiEnforcement()) : null;
        authenticationRequired = dcrConfiguration.getAuthenticationRequired() != null ?
                String.valueOf(dcrConfiguration.getAuthenticationRequired()) : null;
        mandateSSA = dcrConfiguration.getMandateSSA() != null ?
                String.valueOf(dcrConfiguration.getMandateSSA()) : null;
        ssaJwks = dcrConfiguration.getSsaJwks();

        addAttribute(attributes, ENABLE_FAPI_ENFORCEMENT, enableFapiEnforcement);
        addAttribute(attributes, CLIENT_AUTHENTICATION_REQUIRED, authenticationRequired);
        addAttribute(attributes, SSA_JWKS, ssaJwks);
        addAttribute(attributes, MANDATE_SSA, mandateSSA);

        resourceAdd.setAttributes(attributes);

        return resourceAdd;
    }

    private void addAttribute(List<Attribute> attributeList, String key, String value) {

        if (StringUtils.isNotBlank(value)) {
            Attribute attribute = new Attribute();
            attribute.setKey(key);
            attribute.setValue(value);
            attributeList.add(attribute);
        }
    }

}
