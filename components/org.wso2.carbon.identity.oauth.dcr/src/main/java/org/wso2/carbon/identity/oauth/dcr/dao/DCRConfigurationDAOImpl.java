package org.wso2.carbon.identity.oauth.dcr.dao;

import org.wso2.carbon.identity.configuration.mgt.core.ConfigurationManager;
import org.wso2.carbon.identity.configuration.mgt.core.exception.ConfigurationManagementException;
import org.wso2.carbon.identity.configuration.mgt.core.model.Resource;
import org.wso2.carbon.identity.configuration.mgt.core.model.ResourceAdd;
import org.wso2.carbon.identity.oauth.dcr.exception.DCRMServerException;
import org.wso2.carbon.identity.oauth.dcr.internal.DCRDataHolder;
import org.wso2.carbon.identity.oauth.dcr.model.DCRConfiguration;
import org.wso2.carbon.identity.oauth.dcr.util.DCRConfigUtils;

import static org.wso2.carbon.identity.configuration.mgt.core.constant.ConfigurationConstants.
        ErrorMessages.ERROR_CODE_RESOURCE_DOES_NOT_EXISTS;
import static org.wso2.carbon.identity.configuration.mgt.core.constant.ConfigurationConstants.ErrorMessages.ERROR_CODE_RESOURCE_TYPE_DOES_NOT_EXISTS;
import static org.wso2.carbon.identity.oauth.dcr.DCRConfigErrorMessage.ERROR_CODE_DCR_CONFIG_RETRIEVE;
import static org.wso2.carbon.identity.oauth.dcr.DCRMConstants.DCR_CONFIG_RESOURCE_NAME;
import static org.wso2.carbon.identity.oauth.dcr.DCRMConstants.DCR_CONFIG_RESOURCE_TYPE_NAME;
import static org.wso2.carbon.identity.oauth.dcr.util.DCRConfigErrorUtils.handleServerException;

/**
 * DAO layer for DCR Configurations.
 */
public class DCRConfigurationDAOImpl implements DCRConfigurationDAO {

    /**
     * {@inheritDoc}
     */
    @Override
    public DCRConfiguration getDCRConfigurationByTenantDomain(String tenantDomain) throws DCRMServerException {

        try {
            Resource resource = getResource(DCR_CONFIG_RESOURCE_TYPE_NAME, DCR_CONFIG_RESOURCE_NAME);
            DCRConfiguration dcrConfiguration;
            if (resource == null) {
                dcrConfiguration = DCRConfigUtils.getServerConfiguration();
            } else {
                dcrConfiguration = DCRConfigUtils.parseResource(resource);
            }
            return dcrConfiguration;
        } catch (ConfigurationManagementException e) {
            throw handleServerException(ERROR_CODE_DCR_CONFIG_RETRIEVE, e, tenantDomain);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setDCRConfigurationByTenantDomain(DCRConfiguration dcrConfiguration, String tenantDomain)
            throws DCRMServerException {

        try {
            ResourceAdd resourceAdd = DCRConfigUtils.parseConfig(dcrConfiguration);
            getConfigurationManager().replaceResource(DCR_CONFIG_RESOURCE_TYPE_NAME, resourceAdd);
        } catch (ConfigurationManagementException e) {
            throw handleServerException(ERROR_CODE_DCR_CONFIG_RETRIEVE, e, tenantDomain);
        }
    }

    /**
     * Retrieve the ConfigurationManager instance from the DCRDataHolder.
     *
     * @return ConfigurationManager The ConfigurationManager instance.
     */
    private ConfigurationManager getConfigurationManager() {

        return DCRDataHolder.getInstance().getConfigurationManager();
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
