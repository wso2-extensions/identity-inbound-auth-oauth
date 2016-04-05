/*
 * Copyright (c) 2013, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth2.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceRegistration;
import org.osgi.service.component.ComponentContext;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.application.mgt.listener.ApplicationMgtListener;
import org.wso2.carbon.identity.base.IdentityRuntimeException;
import org.wso2.carbon.identity.core.util.IdentityCoreInitializedEvent;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.OAuth2Service;
import org.wso2.carbon.identity.oauth2.OAuth2TokenValidationService;
import org.wso2.carbon.identity.oauth2.dao.SQLQueries;
import org.wso2.carbon.identity.user.store.configuration.listener.UserStoreConfigListener;
import org.wso2.carbon.stratos.common.listeners.TenantMgtListener;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

/**
 * @scr.component name="identity.oauth2.component" immediate="true"
 * @scr.reference name="identity.application.management.component"
 * interface=
 * "org.wso2.carbon.identity.application.mgt.ApplicationManagementService"
 * cardinality="1..1" policy="dynamic"
 * bind="setApplicationMgtService"
 * unbind="unsetApplicationMgtService"
 * @scr.reference name="identityCoreInitializedEventService"
 * interface="org.wso2.carbon.identity.core.util.IdentityCoreInitializedEvent" cardinality="1..1"
 * policy="dynamic" bind="setIdentityCoreInitializedEventService" unbind="unsetIdentityCoreInitializedEventService"
 */
public class OAuth2ServiceComponent {
    private static Log log = LogFactory.getLog(OAuth2ServiceComponent.class);
    private static BundleContext bundleContext;

    protected void activate(ComponentContext context) {
        //Registering OAuth2Service as a OSGIService
        bundleContext = context.getBundleContext();
        bundleContext.registerService(OAuth2Service.class.getName(), new OAuth2Service(), null);
        // exposing server configuration as a service 
        OAuthServerConfiguration oauthServerConfig = OAuthServerConfiguration.getInstance();
        bundleContext.registerService(OAuthServerConfiguration.class.getName(), oauthServerConfig, null);
        OAuth2TokenValidationService tokenValidationService = new OAuth2TokenValidationService();
        bundleContext.registerService(OAuth2TokenValidationService.class.getName(), tokenValidationService, null);
        if (log.isDebugEnabled()) {
            log.debug("Identity OAuth bundle is activated");
        }

        ServiceRegistration tenantMgtListenerSR = bundleContext.registerService(TenantMgtListener.class.getName(),
                new OAuthTenantMgtListenerImpl(), null);
        if (tenantMgtListenerSR != null) {
            if (log.isDebugEnabled()) {
                log.debug("OAuth - TenantMgtListener registered.");
            }
        } else {
            log.error("OAuth - TenantMgtListener could not be registered.");
        }

        ServiceRegistration userStoreConfigEventSR = bundleContext.registerService(
                UserStoreConfigListener.class.getName(), new OAuthUserStoreConfigListenerImpl(), null);
        if (userStoreConfigEventSR != null) {
            if (log.isDebugEnabled()) {
                log.debug("OAuth - UserStoreConfigListener registered.");
            }
        } else {
            log.error("OAuth - UserStoreConfigListener could not be registered.");
        }

        ServiceRegistration oauthApplicationMgtListenerSR = bundleContext.registerService(ApplicationMgtListener.class.getName(),
                new OAuthApplicationMgtListener(), null);
        if (oauthApplicationMgtListenerSR != null) {
            if (log.isDebugEnabled()) {
                log.debug("OAuth - ApplicationMgtListener registered.");
            }
        } else {
            log.error("OAuth - ApplicationMgtListener could not be registered.");
        }
        if(checkPKCESupport()) {
            OAuth2ServiceComponentHolder.setPkceEnabled(true);
            if(log.isInfoEnabled()) {
                log.info("PKCE Support enabled.");
            }
        } else {
            OAuth2ServiceComponentHolder.setPkceEnabled(false);
            if(log.isInfoEnabled()) {
                log.info("PKCE Support is disabled.");
            }
        }
    }

    /**
     * Set Application management service implementation
     *
     * @param applicationMgtService Application management service
     */
    protected void setApplicationMgtService(ApplicationManagementService applicationMgtService) {
        if (log.isDebugEnabled()) {
            log.debug("ApplicationManagementService set in Identity OAuth2ServiceComponent bundle");
        }
        OAuth2ServiceComponentHolder.setApplicationMgtService(applicationMgtService);
    }

    /**
     * Unset Application management service implementation
     *
     * @param applicationMgtService Application management service
     */
    protected void unsetApplicationMgtService(ApplicationManagementService applicationMgtService) {
        if (log.isDebugEnabled()) {
            log.debug("ApplicationManagementService unset in Identity OAuth2ServiceComponent bundle");
        }
        OAuth2ServiceComponentHolder.setApplicationMgtService(null);
    }

    protected void unsetIdentityCoreInitializedEventService(IdentityCoreInitializedEvent identityCoreInitializedEvent) {
        /* reference IdentityCoreInitializedEvent service to guarantee that this component will wait until identity core
         is started */
    }

    protected void setIdentityCoreInitializedEventService(IdentityCoreInitializedEvent identityCoreInitializedEvent) {
        /* reference IdentityCoreInitializedEvent service to guarantee that this component will wait until identity core
         is started */
    }

    private boolean checkPKCESupport() {
        Connection connection = null;
        try {
            connection = IdentityDatabaseUtil.getDBConnection();
        } catch (IdentityRuntimeException e) {
            return false;
        }


        if(connection != null) {
            try {
                PreparedStatement preparedStatement = connection.prepareStatement(SQLQueries.RETRIEVE_PKCE_TABLE);
                ResultSet resultSet = preparedStatement.executeQuery();
                if(resultSet != null) {
                    //following statement will throw SQLException if the column is not found
                    resultSet.findColumn("_PKCE_MANDATORY");
                    //if we are here then the column exists, so PKCE is supported by the database.
                    return true;
                }
            } catch (SQLException e) {

            } finally {
                try {
                    connection.close();
                } catch (SQLException e) {

                }
            }
        }
        return false;
    }
}
