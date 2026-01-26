/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.oauth.listener;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.AssociatedRolesConfig;
import org.wso2.carbon.identity.application.common.model.InboundAuthenticationConfig;
import org.wso2.carbon.identity.application.common.model.LocalAndOutboundAuthenticationConfig;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.application.mgt.inbound.dto.ApplicationDTO;
import org.wso2.carbon.identity.application.mgt.inbound.dto.InboundProtocolsDTO;
import org.wso2.carbon.identity.core.AbstractIdentityUserOperationEventListener;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.dto.OAuthConsumerAppDTO;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.common.User;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import java.util.Map;

/**
 * User operation event listener that automatically creates a standard-based OAuth2/OIDC application
 * when a new agent is created in the system.
 *
 * <p>This listener triggers only for agent creation (users in the AGENT userstore domain),
 * not for regular user creation.</p>
 */
public class UserApplicationCreationListener extends AbstractIdentityUserOperationEventListener {

    private static final Log log = LogFactory.getLog(UserApplicationCreationListener.class);

    @Override
    public int getExecutionOrderId() {

        int orderId = getOrderId();
        if (orderId != IdentityCoreConstants.EVENT_LISTENER_ORDER_ID) {
            return orderId;
        }
        // Execute after most other listeners
        return 99;
    }

    @Override
    public boolean doPostAddUserWithID(User user, Object credential, String[] roleList,
                                       Map<String, String> claims, String profile,
                                       UserStoreManager userStoreManager) throws UserStoreException {

        // Check if the listener is enabled
        if (!isEnable()) {
            return true;
        }

        try {

            String username = user.getUsername();
            String userStoreDomain = user.getUserStoreDomain();
            int tenantId = userStoreManager.getTenantId();
            String tenantDomain = IdentityTenantUtil.getTenantDomain(tenantId);

            // Get the agent identity userStore name from configuration
            String agentUserStoreName = IdentityUtil.getAgentIdentityUserstoreName();

            // Check if the user being created is an agent
            // Agents have the AGENT userStore domain prefix
            if (StringUtils.isBlank(userStoreDomain) ||
                    !agentUserStoreName.equalsIgnoreCase(userStoreDomain)) {
                // This is a regular user, not an agent. Skip application creation.
                if (log.isDebugEnabled()) {
                    log.debug("User " + username + " is not an agent (domain: " + userStoreDomain +
                            "). Skipping application creation.");
                }
                return true;
            }

            // Create the OAuth2/OIDC application for the agent
            createStandardBasedApplication(username, tenantDomain);
            
            return true;

        } catch (IdentityApplicationManagementException e) {
            log.error("Error occurred while creating standard-based application for agent: " +
                    user.getUsername(), e);
            // Return true to not block agent creation, but log the error
            return true;
        }

    }
    
    private void createStandardBasedApplication(String username, String tenantDomain)
            throws IdentityApplicationManagementException {
        
        String applicationName = UserCoreUtil.removeDomainFromName(username);

        // Create a new ServiceProvider (Application)
        ServiceProvider serviceProvider = new ServiceProvider();
        serviceProvider.setApplicationName("Agent-" + applicationName);
        serviceProvider.setDescription("Standard-based OAuth2/OIDC application auto-created for agent");
        serviceProvider.setTemplateId("custom-application-oidc");
        AssociatedRolesConfig associatedRolesConfig = new AssociatedRolesConfig();
        associatedRolesConfig.setAllowedAudience("APPLICATION");
        LocalAndOutboundAuthenticationConfig localAndOutboundAuthenticationConfig =
                new LocalAndOutboundAuthenticationConfig();
        InboundAuthenticationConfig inboundAuthenticationConfig = new InboundAuthenticationConfig();
        serviceProvider.setInboundAuthenticationConfig(inboundAuthenticationConfig);
        serviceProvider.setLocalAndOutBoundAuthenticationConfig(localAndOutboundAuthenticationConfig);
        serviceProvider.setAssociatedRolesConfig(associatedRolesConfig);
        serviceProvider.setApplicationResourceId(username);

        OAuthConsumerAppDTO consumerAppDTO = new OAuthConsumerAppDTO();
        consumerAppDTO.setOAuthVersion("OAuth-2.0");
        consumerAppDTO.setGrantTypes("client_credentials");
        consumerAppDTO.setTokenType("JWT");
        consumerAppDTO.setTokenBindingType("None");

        InboundProtocolsDTO inboundProtocolsDTO = new InboundProtocolsDTO();
        inboundProtocolsDTO.addProtocolConfiguration(consumerAppDTO);

        // Build ApplicationDTO using the builder pattern (same as framework does)
        ApplicationDTO applicationDTO = new ApplicationDTO.Builder()
                .serviceProvider(serviceProvider)
                .inboundProtocolConfigurationDto(inboundProtocolsDTO)
                .build();

        ApplicationManagementService applicationManagementService =
                OAuthComponentServiceHolder.getInstance().getApplicationManagementService();

        String applicationResourceId = applicationManagementService.createApplication(
                applicationDTO, tenantDomain, username);

        log.info("Created application with ID: " + applicationResourceId);
    }

}
