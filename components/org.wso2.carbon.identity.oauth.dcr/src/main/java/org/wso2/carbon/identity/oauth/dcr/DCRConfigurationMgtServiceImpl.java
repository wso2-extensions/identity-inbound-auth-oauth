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

import org.wso2.carbon.identity.base.IdentityRuntimeException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.dcr.exception.DCRMClientException;
import org.wso2.carbon.identity.oauth.dcr.exception.DCRMServerException;
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
    public DCRConfiguration getDCRConfiguration(String tenantDomain) throws DCRMClientException, DCRMServerException {

        validateTenantDomain(tenantDomain);

        return DCRDataHolder.getInstance()
                .getDCRConfigurationByTenantDomain(tenantDomain);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setDCRConfiguration(DCRConfiguration dcrConfigurationConfig, String tenantDomain)
            throws DCRMClientException, DCRMServerException {

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
