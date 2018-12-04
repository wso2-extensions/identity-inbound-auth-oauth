/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.common.cryptooperators;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.base.api.ServerConfigurationService;
import org.wso2.carbon.crypto.api.CertificateInfo;
import org.wso2.carbon.crypto.api.CryptoContext;
import org.wso2.carbon.crypto.api.KeyResolver;
import org.wso2.carbon.crypto.api.PrivateKeyInfo;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.internal.CommonUtilDataHolder;

import java.security.cert.CertificateException;

import static org.wso2.carbon.base.MultitenantConstants.SUPER_TENANT_ID;

/**
 * Extension of {@link KeyResolver}
 * Instances of this class resolves certificate and private key details related to service providers.
 */
public class ServiceProviderKeyResolver extends KeyResolver {

    private static final String PRIMARY_KEYSTORE_KEY_ALIAS_PROPERTY_PATH = "Security.KeyStore.KeyAlias";
    private static final String PRIMARY_KEYSTORE_KEY_PASSWORD_PROPERTY_PATH = "Security.KeyStore.KeyPassword";

    private static Log log = LogFactory.getLog(ServiceProviderKeyResolver.class);

    private ServerConfigurationService serverConfigurationService;

    /**
     * Constructor for {@link ServiceProviderKeyResolver}.
     *
     * @param serverConfigurationService : carbon.xml configuration as a service.
     */
    public ServiceProviderKeyResolver(ServerConfigurationService serverConfigurationService) {

        this.serverConfigurationService = serverConfigurationService;
    }

    @Override
    public boolean isApplicable(CryptoContext cryptoContext) {

        if (cryptoContext.getIdentifier() != null) {
            return true;
        }
        return false;
    }

    /**
     * Returns private key information related to given service provider context.
     *
     * @param cryptoContext : : Context information related private key that needs to be resolved.
     * @return {@link PrivateKeyInfo} key alias and password of the related private key.
     */
    @Override
    public PrivateKeyInfo getPrivateKeyInfo(CryptoContext cryptoContext) {

        String keyAlias;
        String keyPassword;
        if (SUPER_TENANT_ID == cryptoContext.getTenantId()) {
            keyAlias = serverConfigurationService.getFirstProperty(PRIMARY_KEYSTORE_KEY_ALIAS_PROPERTY_PATH);
            keyPassword = serverConfigurationService.getFirstProperty(PRIMARY_KEYSTORE_KEY_PASSWORD_PROPERTY_PATH);
        } else {
            keyAlias = cryptoContext.getTenantDomain();
            keyPassword = null; // Key password will be internally handled by the KeyStoreManager
        }
        return new PrivateKeyInfo(keyAlias, keyPassword);
    }

    /**
     * Returns certificate and application ID related to the given {@link CryptoContext}.
     *
     * @param cryptoContext : Context information related certificate that needs to be resolved.
     * @return {@link CertificateInfo} certificate and application ID.
     */
    @Override
    public CertificateInfo getCertificateInfo(CryptoContext cryptoContext) {

        String clientId = cryptoContext.getIdentifier();
        String tenantDomain = cryptoContext.getTenantDomain();
        try {
            ServiceProvider serviceProvider = CommonUtilDataHolder.getApplicationMgtService()
                    .getServiceProviderByClientId(clientId, cryptoContext.getType(), tenantDomain);
            // Get the certificate content.
            String certificateContent = serviceProvider.getCertificateContent();
            if (StringUtils.isNotBlank(certificateContent)) {
                // Build the Certificate object from cert content.
                return new CertificateInfo(String.valueOf(serviceProvider.getApplicationID()),
                        IdentityUtil.convertPEMEncodedContentToCertificate(certificateContent));
            } else {
                log.error("Public certificate not configured for Service Provider with " +
                        "client_id: " + clientId + " of tenantDomain: " + tenantDomain);
            }
        } catch (CertificateException e) {
            String errorMessage = String.format("Error occurred while converting the PEM encoded certificate " +
                    "of service provider with client ID : %s.", clientId);
            log.error(errorMessage, e);
        } catch (IdentityApplicationManagementException e) {
            log.error(String.format("Error occurred while retrieving %s service provider with client id = %s",
                    cryptoContext.getType(), clientId));
        }
        return new CertificateInfo(null, null);
    }
}
