package org.wso2.carbon.identity.oauth.dcr.dao;

import org.wso2.carbon.identity.oauth.dcr.exception.DCRMServerException;
import org.wso2.carbon.identity.oauth.dcr.model.DCRConfiguration;

/**
 * Perform CRUD operations for {@link DCRConfiguration}.
 */
public interface DCRConfigurationDAO {

    /**
     * Get the DCR configuration of a tenant.
     *
     * @param tenantDomain The tenant domain.
     * @return DCRConfiguration The configuration model.
     * @throws DCRMServerException DCRMServerException
     */
    DCRConfiguration getDCRConfigurationByTenantDomain(String tenantDomain) throws DCRMServerException;

    /**
     * Set the DCR configuration of a tenant.
     *
     * @param dcrConfiguration The new DCR configuration to be set.
     * @param tenantDomain The tenant domain.
     * @throws DCRMServerException DCRMServerException
     */
    void setDCRConfigurationByTenantDomain(DCRConfiguration dcrConfiguration, String tenantDomain)
            throws DCRMServerException;
}
