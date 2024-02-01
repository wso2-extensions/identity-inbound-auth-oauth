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

package org.wso2.carbon.identity.oauth;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementClientException;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementServerException;
import org.wso2.carbon.identity.application.common.model.InboundAuthenticationRequestConfig;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.mgt.inbound.InboundFunctions;
import org.wso2.carbon.identity.application.mgt.inbound.dto.InboundProtocolConfigurationDTO;
import org.wso2.carbon.identity.application.mgt.inbound.dto.InboundProtocolsDTO;
import org.wso2.carbon.identity.application.mgt.inbound.protocol.ApplicationInboundAuthConfigHandler;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.cors.mgt.core.exception.CORSManagementServiceClientException;
import org.wso2.carbon.identity.cors.mgt.core.exception.CORSManagementServiceException;
import org.wso2.carbon.identity.cors.mgt.core.exception.CORSManagementServiceServerException;
import org.wso2.carbon.identity.cors.mgt.core.model.CORSOrigin;
import org.wso2.carbon.identity.oauth.dto.OAuthConsumerAppDTO;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;

import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.stream.Collectors;

import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.StandardInboundProtocols.OAUTH2;

/**
 * OAuth Protocol Handler. This class is responsible for handling the protocol operations for OAuth2 according to the
 * application management service. No audit logs will be published from this class since those will be published from
 * the application management service.
 */
public class OauthInboundAuthConfigHandler implements ApplicationInboundAuthConfigHandler {
    
    private static final Log log = LogFactory.getLog(OauthInboundAuthConfigHandler.class);
    private static final String TENANT_NAME_FROM_CONTEXT = "TenantNameFromContext";
    
    @Override
    public boolean canHandle(InboundProtocolsDTO inboundProtocolsDTO) {
        
        return inboundProtocolsDTO.getInboundProtocolConfigurationMap().containsKey(OAUTH2);
    }
    
    @Override
    public boolean canHandle(String protocolName) {
        
        return StringUtils.equals(FrameworkConstants.StandardInboundProtocols.OAUTH2,
                protocolName.toLowerCase(Locale.ROOT));
    }
    
    /**
     * Create OAuth application. Before calling this method, the can handle method should be called to identify whether
     * this handler can actually handle the request.
     *
     * @param application      Service provider.
     * @param inboundProtocols Inbound protocols DTO. This should contain OAuth2 configuration.
     * @return InboundAuthenticationRequestConfig object.
     * @throws IdentityApplicationManagementException IdentityApplicationManagementException.
     */
    @Override
    public InboundAuthenticationRequestConfig handleConfigCreation(ServiceProvider application,
                                                                   InboundProtocolsDTO inboundProtocols)
            throws IdentityApplicationManagementException {
        
        OAuthConsumerAppDTO consumerApp = (OAuthConsumerAppDTO) inboundProtocols.getInboundProtocolConfigurationMap()
                .get(OAUTH2);
        // Creating the protocol details without auditing the OAuth protocol creation details because those details
        // will be audited from the framework level.
        try {
            return createOAuthProtocol(consumerApp);
        } catch (IdentityOAuthClientException e) {
            throw new IdentityApplicationManagementClientException(e.getErrorCode(), e.getMessage(), e);
        } catch (IdentityOAuthServerException e) {
            throw new IdentityApplicationManagementServerException(e.getErrorCode(), e.getMessage(), e);
        } catch (IdentityOAuthAdminException e) {
            throw new IdentityApplicationManagementException(e.getErrorCode(), e.getMessage(), e);
        }
    }
    
    /**
     * Update OAuth application. Before calling this method, the can handle method should be called to identify whether
     * this handler can actually handle the request.
     *
     * @param application                     Service provider.
     * @param inboundProtocolConfigurationDTO Inbound protocol configuration DTO. This should be an instance of
     *                                        OAuthConsumerAppDTO
     * @return InboundAuthenticationRequestConfig object.
     * @throws IdentityApplicationManagementException IdentityApplicationManagementException.
     */
    @Override
    public InboundAuthenticationRequestConfig handleConfigUpdate(
            ServiceProvider application, InboundProtocolConfigurationDTO inboundProtocolConfigurationDTO)
            throws IdentityApplicationManagementException {
        
        if (!(inboundProtocolConfigurationDTO instanceof OAuthConsumerAppDTO)) {
            throw new IdentityApplicationManagementClientException(
                    "Invalid inbound protocol configuration type provided for OAuth2 protocol.");
        }
        OAuthConsumerAppDTO consumerAppDTO = (OAuthConsumerAppDTO) inboundProtocolConfigurationDTO;
        // Updating the protocol details without auditing the OAuth protocol details because those details will be
        // audited from the framework level.
        String tenantDomain = getTenantDomainFromContext();
        List<String> existingCORSOrigins = null;
        
        // First we identify whether this is a insert or update.
        try {
            Optional<String> optionalInboundAuthKey = InboundFunctions.getInboundAuthKey(application, OAUTH2);
            
            // Retrieve the existing CORS origins for the application.
            existingCORSOrigins = OAuthComponentServiceHolder.getInstance().getCorsManagementService()
                    .getApplicationCORSOrigins(application.getApplicationResourceId(), tenantDomain)
                    .stream().map(CORSOrigin::getOrigin).collect(Collectors.toList());
            
            // Update the CORS origins.
            List<String> corsOrigins = consumerAppDTO.getAllowedOrigins();
            OAuthComponentServiceHolder.getInstance().getCorsManagementService().setCORSOrigins(
                    application.getApplicationResourceId(), corsOrigins, tenantDomain);
            
            if (optionalInboundAuthKey.isPresent()) {
                // Update an existing application.
                OAuthConsumerAppDTO oauthApp = OAuth2ServiceComponentHolder.getInstance().getOAuthAdminService()
                        .getOAuthApplicationData(optionalInboundAuthKey.get());
                
                if (!StringUtils.equals(oauthApp.getOauthConsumerKey(), consumerAppDTO.getOauthConsumerKey())) {
                    throw new IdentityOAuthClientException("Invalid ClientID provided for update.");
                }
                if (!StringUtils.equals(oauthApp.getOauthConsumerSecret(), consumerAppDTO.getOauthConsumerSecret())) {
                    throw new IdentityOAuthClientException("Invalid ClientSecret provided for update.");
                }
                OAuth2ServiceComponentHolder.getInstance().getOAuthAdminService().updateConsumerApplication(
                        consumerAppDTO, false);
                return createInboundAuthRequestConfig(consumerAppDTO);
            } else {
                // Create a new application.
                return createOAuthProtocol(consumerAppDTO);
            }
            
        } catch (IdentityOAuthAdminException e) {
            /*
            If an IdentityOAuthAdminException exception is thrown after the CORS update, then the application
            update has failed. Therefore rollback the update on CORS origins.
             */
            try {
                OAuthComponentServiceHolder.getInstance().getCorsManagementService().setCORSOrigins
                        (application.getApplicationResourceId(), existingCORSOrigins, tenantDomain);
            } catch (CORSManagementServiceClientException corsManagementServiceClientException) {
                throw new IdentityApplicationManagementClientException(
                        corsManagementServiceClientException.getMessage(), corsManagementServiceClientException);
            } catch (CORSManagementServiceServerException corsManagementServiceServerException) {
                throw new IdentityApplicationManagementServerException(
                        corsManagementServiceServerException.getMessage(), corsManagementServiceServerException);
            } catch (CORSManagementServiceException corsManagementServiceException) {
                throw new IdentityApplicationManagementException(
                        corsManagementServiceException.getMessage(), corsManagementServiceException);
            }
            // Handle all the identity exceptions from a single place to avoid repeating the same rollback logic.
            throw handleException(e);
        } catch (CORSManagementServiceClientException corsManagementServiceClientException) {
            throw new IdentityApplicationManagementClientException(
                    corsManagementServiceClientException.getMessage(), corsManagementServiceClientException);
        } catch (CORSManagementServiceServerException corsManagementServiceServerException) {
            throw new IdentityApplicationManagementServerException(
                    corsManagementServiceServerException.getMessage(), corsManagementServiceServerException);
        } catch (CORSManagementServiceException corsManagementServiceException) {
            throw new IdentityApplicationManagementException(
                    corsManagementServiceException.getMessage(), corsManagementServiceException);
        }
    }
    
    /**
     * This method is used to handle the deletion of OAuth protocol configurations.
     * @param consumerKey Consumer key of the OAuth application.
     * @throws IdentityApplicationManagementException IdentityApplicationManagementException.
     */
    @Override
    public void handleConfigDeletion(String consumerKey) throws IdentityApplicationManagementException {
        
        try {
            OAuth2ServiceComponentHolder.getInstance().getOAuthAdminService().removeOAuthApplicationData(consumerKey,
                    false);
        } catch (IdentityOAuthClientException e) {
            throw new IdentityApplicationManagementClientException(e.getErrorCode(), e.getMessage(), e);
        } catch (IdentityOAuthServerException e) {
            throw new IdentityApplicationManagementServerException(e.getErrorCode(), e.getMessage(), e);
        } catch (IdentityOAuthAdminException e) {
            throw new IdentityApplicationManagementException(e.getErrorCode(), e.getMessage(), e);
        }
    }
    
    /**
     * This method is used to handle the retrieval of OAuth protocol configurations.
     *
     * @param consumerKey Consumer key of the OAuth application.
     * @return OAuthConsumerAppDTO object.
     * @throws IdentityApplicationManagementException IdentityApplicationManagementException.
     */
    @Override
    public OAuthConsumerAppDTO handleConfigRetrieval(String consumerKey) throws IdentityApplicationManagementException {
        
        try {
            return OAuth2ServiceComponentHolder.getInstance().getOAuthAdminService().getOAuthApplicationData(
                    consumerKey);
        } catch (IdentityOAuthClientException e) {
            throw new IdentityApplicationManagementClientException(e.getErrorCode(), e.getMessage(), e);
        } catch (IdentityOAuthServerException e) {
            throw new IdentityApplicationManagementServerException(e.getErrorCode(), e.getMessage(), e);
        } catch (IdentityOAuthAdminException e) {
            throw new IdentityApplicationManagementException(e.getErrorCode(), e.getMessage(), e);
        }
    }
    
    /**
     * Create OAuth application. This method is for internal use only. Create OAuth2 protocol by calling the
     * AuthAdminService.
     *
     * @param consumerApp OAuth application DTO.
     * @return InboundAuthenticationRequestConfig object.
     * @throws IdentityOAuthAdminException IdentityOAuthAdminException.
     */
    private InboundAuthenticationRequestConfig createOAuthProtocol(OAuthConsumerAppDTO consumerApp)
            throws IdentityOAuthAdminException {
        
        OAuthConsumerAppDTO createdOAuthApp = OAuth2ServiceComponentHolder.getInstance().getOAuthAdminService()
                .registerAndRetrieveOAuthApplicationData(consumerApp, false);
        return createInboundAuthRequestConfig(createdOAuthApp);
    }
    
    private static InboundAuthenticationRequestConfig createInboundAuthRequestConfig(
            OAuthConsumerAppDTO oAuthConsumerAppDTO) {
        
        InboundAuthenticationRequestConfig oidcInbound = new InboundAuthenticationRequestConfig();
        oidcInbound.setInboundAuthType(FrameworkConstants.StandardInboundProtocols.OAUTH2);
        oidcInbound.setData(oAuthConsumerAppDTO.getAuditLogData());
        oidcInbound.setInboundAuthKey(oAuthConsumerAppDTO.getOauthConsumerKey());
        return oidcInbound;
    }
    
    /**
     * Retrieves loaded tenant domain from carbon context.
     *
     * @return tenant domain of the request is being served.
     */
    public static String getTenantDomainFromContext() {
        
        String tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
        if (IdentityUtil.threadLocalProperties.get().get(TENANT_NAME_FROM_CONTEXT) != null) {
            tenantDomain = (String) IdentityUtil.threadLocalProperties.get().get(TENANT_NAME_FROM_CONTEXT);
        }
        return tenantDomain;
    }
    
    private static IdentityApplicationManagementException handleException(IdentityOAuthAdminException e) {
        
        if (e instanceof IdentityOAuthClientException) {
            return new IdentityApplicationManagementClientException(e.getErrorCode(), e.getMessage(), e);
        } else if (e instanceof  IdentityOAuthServerException) {
            return new IdentityApplicationManagementServerException(e.getErrorCode(), e.getMessage(), e);
        } else {
            return new IdentityApplicationManagementException(e.getErrorCode(), e.getMessage(), e);
        }
    }
}
