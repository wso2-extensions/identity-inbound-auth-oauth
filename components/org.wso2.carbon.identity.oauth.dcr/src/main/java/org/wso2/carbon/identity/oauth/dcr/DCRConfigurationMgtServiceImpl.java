package org.wso2.carbon.identity.oauth.dcr;

import org.wso2.carbon.identity.base.IdentityRuntimeException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.dcr.exception.DCRMClientException;
import org.wso2.carbon.identity.oauth.dcr.exception.DCRMException;
import org.wso2.carbon.identity.oauth.dcr.internal.DCRDataHolder;
import org.wso2.carbon.identity.oauth.dcr.model.DCRConfiguration;

import static org.wso2.carbon.identity.oauth.dcr.util.DCRConfigErrorUtils.handleClientException;

/**
 * Implementation of Service for managing the DCR configurations of a tenant.
 */
public class DCRConfigurationMgtServiceImpl implements DCRConfigurationMgtService {

    /**
     * {@inheritDoc}
     */
    @Override
    public DCRConfiguration getDCRConfiguration(String tenantDomain) throws DCRMException {

        validateTenantDomain(tenantDomain);

        return DCRDataHolder.getInstance()
                .getDCRConfigurationByTenantDomain(tenantDomain);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setDCRConfiguration(DCRConfiguration dcrConfigurationConfig, String tenantDomain) throws DCRMException {

        validateTenantDomain(tenantDomain);

        DCRDataHolder.getInstance()
                .setDCRConfigurationByTenantDomain(dcrConfigurationConfig, tenantDomain);
    }

    /**
     * Validate the tenant domain.
     *
     * @param tenantDomain The tenant domain.
     * @throws DCRMClientException
     */
    private void validateTenantDomain(String tenantDomain)
            throws DCRMClientException {

        try {
            IdentityTenantUtil.getTenantId(tenantDomain);
        } catch (IdentityRuntimeException e) {
            throw handleClientException(DCRConfigErrorMessage.ERROR_CODE_INVALID_TENANT_DOMAIN, e, tenantDomain);
        }
    }

}
