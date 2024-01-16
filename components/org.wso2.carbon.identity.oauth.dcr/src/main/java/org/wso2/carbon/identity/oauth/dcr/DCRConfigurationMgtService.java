package org.wso2.carbon.identity.oauth.dcr;

import org.wso2.carbon.identity.oauth.dcr.exception.DCRMException;
import org.wso2.carbon.identity.oauth.dcr.model.DCRConfiguration;

/**
 * Service for managing the DCR configurations of a tenant.
 */
public interface DCRConfigurationMgtService {

    /**
     * Get the DCR configurations of a tenant.
     *
     * @param tenantDomain The tenant domain.
     * @return DCRConfiguration Returns an instance of {@code DCRConfiguration} belonging to the tenant.
     * @throws DCRMException
     */
    DCRConfiguration getDCRConfiguration(String tenantDomain) throws DCRMException;

    /**
     * Set the JWT Authenticator configurations of a tenant.
     *
     * @param dcrConfigurationConfig The {@code DCRConfiguration} object to be set.
     * @param tenantDomain                 The tenant domain.
     * @throws DCRMException
     */
    void setDCRConfiguration(DCRConfiguration dcrConfigurationConfig, String tenantDomain) throws DCRMException;
}
