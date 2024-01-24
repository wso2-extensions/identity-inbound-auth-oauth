/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * you may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.dcr.internal;

import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.configuration.mgt.core.ConfigurationManager;
import org.wso2.carbon.identity.configuration.mgt.core.exception.ConfigurationManagementException;
import org.wso2.carbon.identity.configuration.mgt.core.model.Resource;
import org.wso2.carbon.identity.configuration.mgt.core.model.ResourceAdd;
import org.wso2.carbon.identity.oauth.dcr.exception.DCRMServerException;
import org.wso2.carbon.identity.oauth.dcr.handler.RegistrationHandler;
import org.wso2.carbon.identity.oauth.dcr.handler.UnRegistrationHandler;
import org.wso2.carbon.identity.oauth.dcr.model.DCRConfiguration;
import org.wso2.carbon.identity.oauth.dcr.util.DCRConfigUtils;
import org.wso2.carbon.identity.oauth2.token.bindings.TokenBinder;

import java.util.ArrayList;
import java.util.List;

import static org.wso2.carbon.identity.configuration.mgt.core.constant.ConfigurationConstants.ErrorMessages.ERROR_CODE_RESOURCE_DOES_NOT_EXISTS;
import static org.wso2.carbon.identity.configuration.mgt.core.constant.ConfigurationConstants.ErrorMessages.ERROR_CODE_RESOURCE_TYPE_DOES_NOT_EXISTS;
import static org.wso2.carbon.identity.oauth.dcr.DCRConfigErrorMessage.ERROR_CODE_DCR_CONFIGURATION_RETRIEVE;
import static org.wso2.carbon.identity.oauth.dcr.DCRMConstants.DCR_CONFIG_RESOURCE_NAME;
import static org.wso2.carbon.identity.oauth.dcr.DCRMConstants.DCR_CONFIG_RESOURCE_TYPE_NAME;
import static org.wso2.carbon.identity.oauth.dcr.util.DCRConfigErrorUtils.handleServerException;

/**
 * This is the DataHolder class of DynamicClientRegistration bundle. This holds a reference to the
 * ApplicationManagementService.
 * This was deprecated as part of deprecating the legacy identity/register DCR endpoint.
 * The recommendation is to use /identity/oauth2/dcr/v1.1 instead.
 */
@Deprecated
public class DCRDataHolder {

    private static DCRDataHolder thisInstance = new DCRDataHolder();
    private ApplicationManagementService applicationManagementService = null;
    private List<RegistrationHandler> registrationHandlerList = new ArrayList<>();
    private List<UnRegistrationHandler> unRegistrationHandlerList = new ArrayList<>();
    private List<TokenBinder> tokenBinders = new ArrayList<>();
    private ConfigurationManager configurationManager;

    private DCRDataHolder() {

    }

    public static DCRDataHolder getInstance() {

        return thisInstance;
    }

    public ApplicationManagementService getApplicationManagementService() {

        if (applicationManagementService == null) {
            throw new IllegalStateException("ApplicationManagementService is not initialized properly");
        }
        return applicationManagementService;
    }

    public void setApplicationManagementService(ApplicationManagementService applicationManagementService) {

        this.applicationManagementService = applicationManagementService;
    }

    public List<RegistrationHandler> getRegistrationHandlerList() {

        return registrationHandlerList;
    }

    public void setRegistrationHandlerList(
            List<RegistrationHandler> registrationHandlerList) {

        this.registrationHandlerList = registrationHandlerList;
    }

    public List<UnRegistrationHandler> getUnRegistrationHandlerList() {

        return unRegistrationHandlerList;
    }

    public void setUnRegistrationHandlerList(
            List<UnRegistrationHandler> unRegistrationHandlerList) {

        this.unRegistrationHandlerList = unRegistrationHandlerList;
    }

    public List<TokenBinder> getTokenBinders() {

        return tokenBinders;
    }

    public void addTokenBinder(TokenBinder tokenBinder) {

        this.tokenBinders.add(tokenBinder);
    }

    public void removeTokenBinder(TokenBinder tokenBinder) {

        this.tokenBinders.remove(tokenBinder);
    }

    public ConfigurationManager getConfigurationManager() {
        return configurationManager;
    }

    public void setConfigurationManager(ConfigurationManager configurationManager) {
        this.configurationManager = configurationManager;
    }

    public DCRConfiguration getDCRConfigurationByTenantDomain(String tenantDomain) throws DCRMServerException {

        try {
            Resource resource = getResource(DCR_CONFIG_RESOURCE_TYPE_NAME, DCR_CONFIG_RESOURCE_NAME);
            DCRConfiguration dcrConfiguration = DCRConfigUtils.getServerConfiguration();
            if (resource != null) {
                DCRConfigUtils.overrideConfigsWithResource(resource, dcrConfiguration);
            }

            return dcrConfiguration;
        } catch (ConfigurationManagementException e) {
            throw handleServerException(ERROR_CODE_DCR_CONFIGURATION_RETRIEVE, e, tenantDomain);
        }
    }

    public void setDCRConfigurationByTenantDomain(DCRConfiguration dcrConfiguration, String tenantDomain)
            throws DCRMServerException {

        try {
            ResourceAdd resourceAdd = DCRConfigUtils.parseConfig(dcrConfiguration);
            getConfigurationManager().replaceResource(DCR_CONFIG_RESOURCE_TYPE_NAME, resourceAdd);
        } catch (ConfigurationManagementException e) {
            throw handleServerException(ERROR_CODE_DCR_CONFIGURATION_RETRIEVE, e, tenantDomain);
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
    private Resource getResource(String resourceTypeName, String resourceName) throws ConfigurationManagementException {

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

}
