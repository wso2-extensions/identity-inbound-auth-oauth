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
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.application.mgt.listener.ApplicationMgtListener;
import org.wso2.carbon.identity.base.IdentityRuntimeException;
import org.wso2.carbon.identity.core.util.IdentityCoreInitializedEvent;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.OAuth2ScopeService;
import org.wso2.carbon.identity.oauth2.OAuth2Service;
import org.wso2.carbon.identity.oauth2.OAuth2TokenValidationService;
import org.wso2.carbon.identity.oauth2.dao.SQLQueries;
import org.wso2.carbon.identity.oauth2.listener.TenantCreationEventListener;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.user.store.configuration.listener.UserStoreConfigListener;
import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.stratos.common.listeners.TenantMgtListener;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

import static org.wso2.carbon.identity.oauth2.util.OAuth2Util.checkAudienceEnabled;

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
 * @scr.reference name="registry.service"
 * interface="org.wso2.carbon.registry.core.service.RegistryService" cardinality="1..1"
 * policy="dynamic" bind="setRegistryService" unbind="unsetRegistryService"
 */
public class OAuth2ServiceComponent {

    private static Log log = LogFactory.getLog(OAuth2ServiceComponent.class);
    private static BundleContext bundleContext;

    protected void activate(ComponentContext context) {

        int tenantId = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId();
        OAuth2Util.initiateOIDCScopes(tenantId);
        OAuth2Util.initTokenExpiryTimesOfSps(tenantId);
        TenantCreationEventListener scopeTenantMgtListener = new TenantCreationEventListener();
        //Registering OAuth2Service as a OSGIService
        bundleContext = context.getBundleContext();
        bundleContext.registerService(OAuth2Service.class.getName(), new OAuth2Service(), null);
        //Registering OAuth2ScopeService as a OSGIService
        bundleContext.registerService(OAuth2ScopeService.class.getName(), new OAuth2ScopeService(), null);
        //Registering TenantCreationEventListener
        ServiceRegistration scopeTenantMgtListenerSR = bundleContext.registerService(
                TenantMgtListener.class.getName(), scopeTenantMgtListener, null);
        if (scopeTenantMgtListenerSR != null) {
            if (log.isDebugEnabled()) {
                log.debug(" TenantMgtListener is registered");
            }
        } else {
            log.error("TenantMgtListener could not be registered");
        }
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

        ServiceRegistration oauthApplicationMgtListenerSR =
                bundleContext.registerService(ApplicationMgtListener.class.getName(),
                        new OAuthApplicationMgtListener(), null);
        if (oauthApplicationMgtListenerSR != null) {
            if (log.isDebugEnabled()) {
                log.debug("OAuth - ApplicationMgtListener registered.");
            }
        } else {
            log.error("OAuth - ApplicationMgtListener could not be registered.");
        }
        if (checkPKCESupport()) {
            OAuth2ServiceComponentHolder.setPkceEnabled(true);
            log.info("PKCE Support enabled.");
        } else {
            OAuth2ServiceComponentHolder.setPkceEnabled(false);
            log.info("PKCE Support is disabled.");
        }
        if (checkAudienceEnabled()) {
            if (log.isDebugEnabled()) {
                log.debug("OAuth - OIDC audiences enabled.");
            }
            OAuth2ServiceComponentHolder.setAudienceEnabled(true);
        } else {
            if (log.isDebugEnabled()) {
                log.debug("OAuth - OIDC audiences disabled.");
            }
            OAuth2ServiceComponentHolder.setAudienceEnabled(false);
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


        if (connection != null) {
            try {
                String sql;
                if (connection.getMetaData().getDriverName().contains("MySQL")
                        || connection.getMetaData().getDriverName().contains("H2")) {
                    sql = SQLQueries.RETRIEVE_PKCE_TABLE_MYSQL;
                } else if (connection.getMetaData().getDatabaseProductName().contains("DB2")) {
                    sql = SQLQueries.RETRIEVE_PKCE_TABLE_DB2SQL;
                } else if (connection.getMetaData().getDriverName().contains("MS SQL") ||
                        connection.getMetaData().getDriverName().contains("Microsoft")) {
                    sql = SQLQueries.RETRIEVE_PKCE_TABLE_MSSQL;
                } else if (connection.getMetaData().getDriverName().contains("PostgreSQL")) {
                    sql = SQLQueries.RETRIEVE_PKCE_TABLE_MYSQL;
                } else if (connection.getMetaData().getDriverName().contains("Informix")) {
                    // Driver name = "IBM Informix JDBC Driver for IBM Informix Dynamic Server"
                    sql = SQLQueries.RETRIEVE_PKCE_TABLE_INFORMIX;
                } else {
                    sql = SQLQueries.RETRIEVE_PKCE_TABLE_ORACLE;
                }
                PreparedStatement preparedStatement = connection.prepareStatement(sql);
                ResultSet resultSet = preparedStatement.executeQuery();
                if (resultSet != null) {
                    //following statement will throw SQLException if the column is not found
                    resultSet.findColumn("PKCE_MANDATORY");
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

    protected void setRegistryService(RegistryService registryService) {

        if (log.isDebugEnabled()) {
            log.debug("Setting the Registry Service");
        }
        OAuth2ServiceComponentHolder.setRegistryService(registryService);
    }

    protected void unsetRegistryService(RegistryService registryService) {

        if (log.isDebugEnabled()) {
            log.debug("UnSetting the Registry Service");
        }
        OAuth2ServiceComponentHolder.setRegistryService(null);
    }
}
