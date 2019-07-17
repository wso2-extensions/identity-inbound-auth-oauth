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
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticationMethodNameTranslator;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.InboundAuthenticationConfig;
import org.wso2.carbon.identity.application.common.model.InboundAuthenticationRequestConfig;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.application.mgt.listener.ApplicationMgtListener;
import org.wso2.carbon.identity.base.IdentityRuntimeException;
import org.wso2.carbon.identity.core.util.IdentityCoreInitializedEvent;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.IdentityOAuthAdminException;
import org.wso2.carbon.identity.oauth.OAuthAdminService;
import org.wso2.carbon.identity.oauth.OAuthUtil;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dto.OAuthConsumerAppDTO;
import org.wso2.carbon.identity.oauth2.OAuth2ScopeService;
import org.wso2.carbon.identity.oauth2.OAuth2Service;
import org.wso2.carbon.identity.oauth2.OAuth2TokenValidationService;
import org.wso2.carbon.identity.oauth2.client.authentication.BasicAuthClientAuthenticator;
import org.wso2.carbon.identity.oauth2.client.authentication.OAuthClientAuthenticator;
import org.wso2.carbon.identity.oauth2.client.authentication.OAuthClientAuthnService;
import org.wso2.carbon.identity.oauth2.client.authentication.PublicClientAuthenticator;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.dao.SQLQueries;
import org.wso2.carbon.identity.oauth2.listener.TenantCreationEventListener;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.openidconnect.OpenIDConnectClaimFilter;
import org.wso2.carbon.identity.openidconnect.OpenIDConnectClaimFilterImpl;
import org.wso2.carbon.identity.user.store.configuration.listener.UserStoreConfigListener;
import org.wso2.carbon.registry.core.exceptions.RegistryException;
import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.stratos.common.listeners.TenantMgtListener;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.wso2.carbon.identity.oauth.common.OAuthConstants.GrantTypes.AUTHORIZATION_CODE;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.GrantTypes.REFRESH_TOKEN;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OAuthVersions.VERSION_2;
import static org.wso2.carbon.identity.oauth2.util.AppPortalConstants.INBOUND_AUTH2_TYPE;
import static org.wso2.carbon.identity.oauth2.util.AppPortalConstants.USER_PORTAL_APP_DESCRIPTION;
import static org.wso2.carbon.identity.oauth2.util.AppPortalConstants.USER_PORTAL_APP_NAME;
import static org.wso2.carbon.identity.oauth2.util.AppPortalConstants.USER_PORTAL_CONSUMER_KEY;
import static org.wso2.carbon.identity.oauth2.util.AppPortalConstants.USER_PORTAL_PATH;
import static org.wso2.carbon.identity.oauth2.util.OAuth2Util.checkAudienceEnabled;
import static org.wso2.carbon.identity.oauth2.util.OAuth2Util.checkIDPIdColumnAvailable;
import static org.wso2.carbon.utils.multitenancy.MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
import static org.wso2.carbon.utils.multitenancy.MultitenantConstants.SUPER_TENANT_ID;

@Component(
        name = "identity.oauth2.component",
        immediate = true
)
public class OAuth2ServiceComponent {

    private static Log log = LogFactory.getLog(OAuth2ServiceComponent.class);
    private BundleContext bundleContext;

    @Reference(
            name = "framework.authentication.context.method.name.translator",
            service = AuthenticationMethodNameTranslator.class,
            cardinality = ReferenceCardinality.OPTIONAL,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetAuthenticationMethodNameTranslator"
    )
    protected void setAuthenticationMethodNameTranslator(
            AuthenticationMethodNameTranslator authenticationMethodNameTranslator) {

        OAuth2ServiceComponentHolder.setAuthenticationMethodNameTranslator(authenticationMethodNameTranslator);
    }

    protected void unsetAuthenticationMethodNameTranslator(
            AuthenticationMethodNameTranslator authenticationMethodNameTranslator) {

        if (OAuth2ServiceComponentHolder.getAuthenticationMethodNameTranslator() ==
                authenticationMethodNameTranslator) {
            OAuth2ServiceComponentHolder.setAuthenticationMethodNameTranslator(null);
        }
    }

    protected void activate(ComponentContext context) {

        try {
            int tenantId = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId();
            boolean isRecordExist = OAuthTokenPersistenceFactory.getInstance().getScopeClaimMappingDAO().
                    hasScopesPopulated(tenantId);
            if (!isRecordExist) {
                OAuth2Util.initiateOIDCScopes(tenantId);
            }
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
            OAuthClientAuthnService clientAuthnService = new OAuthClientAuthnService();
            bundleContext.registerService(OAuthClientAuthnService.class.getName(), clientAuthnService, null);
            BasicAuthClientAuthenticator basicAuthClientAuthenticator = new BasicAuthClientAuthenticator();
            bundleContext.registerService(OAuthClientAuthenticator.class.getName(), basicAuthClientAuthenticator,
                    null);
            PublicClientAuthenticator publicClientAuthenticator = new PublicClientAuthenticator();
            bundleContext.registerService(OAuthClientAuthenticator.class.getName(), publicClientAuthenticator,
                    null);

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

            ServiceRegistration oauthApplicationMgtListenerSR = bundleContext.registerService(ApplicationMgtListener
                    .class.getName(), new OAuthApplicationMgtListener(), null);
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

            // Register the default OpenIDConnect claim filter
            bundleContext.registerService(OpenIDConnectClaimFilter.class, new OpenIDConnectClaimFilterImpl(), null);
            if (log.isDebugEnabled()) {
                log.debug("Default OpenIDConnect Claim filter registered successfully.");
            }

            // Initiate portal applications.
            initiatePortals();
        } catch (Throwable e) {
            log.error("Error while activating OAuth2ServiceComponent.", e);
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
        if (checkIDPIdColumnAvailable()) {
            if (log.isDebugEnabled()) {
                log.debug("IDP_ID column is available in all relevant tables. " +
                        "Setting isIDPIdColumnEnabled to true.");
            }
            OAuth2ServiceComponentHolder.setIDPIdColumnEnabled(true);
        } else {
            if (log.isDebugEnabled()) {
                log.debug("IDP_ID column is not available in all relevant tables. " +
                        "Setting isIDPIdColumnEnabled to false.");
            }
            OAuth2ServiceComponentHolder.setIDPIdColumnEnabled(false);
        }
    }

    /**
     * Set Application management service implementation
     *
     * @param applicationMgtService Application management service
     */
    @Reference(
            name = "application.mgt.service",
            service = ApplicationManagementService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetApplicationMgtService"
    )
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

    @Reference(
            name = "identity.core.init.event.service",
            service = IdentityCoreInitializedEvent.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetIdentityCoreInitializedEventService"
    )
    protected void setIdentityCoreInitializedEventService(IdentityCoreInitializedEvent identityCoreInitializedEvent) {
        /* reference IdentityCoreInitializedEvent service to guarantee that this component will wait until identity core
         is started */
    }

    private boolean checkPKCESupport() {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false)) {

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

            try (PreparedStatement preparedStatement = connection.prepareStatement(sql);
                 ResultSet resultSet = preparedStatement.executeQuery()) {
                // Following statement will throw SQLException if the column is not found
                resultSet.findColumn("PKCE_MANDATORY");
                // If we are here then the column exists, so PKCE is supported by the database.
                return true;
            }

        } catch (IdentityRuntimeException | SQLException e) {
            return false;
        }

    }

    @Reference(
            name = "registry.service",
            service = RegistryService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRegistryService"
    )
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

    @Reference(
            name = "oauth.client.authenticator",
            service = OAuthClientAuthenticator.class,
            cardinality = ReferenceCardinality.MULTIPLE,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetOAuthClientAuthenticator"
    )
    protected void setOAuthClientAuthenticator(OAuthClientAuthenticator oAuthClientAuthenticator) {

        if (log.isDebugEnabled()) {
            log.debug("Adding OAuth client authentication handler : " + oAuthClientAuthenticator.getName());
        }
        OAuth2ServiceComponentHolder.addAuthenticationHandler(oAuthClientAuthenticator);
    }

    protected void unsetOAuthClientAuthenticator(OAuthClientAuthenticator oAuthClientAuthenticator) {

        if (log.isDebugEnabled()) {
            log.debug("UnSetting the Registry Service");
        }
        OAuth2ServiceComponentHolder.getAuthenticationHandlers().remove(oAuthClientAuthenticator);
    }

    /**
     * Initiate portal applications.
     *
     * @throws IdentityApplicationManagementException IdentityApplicationManagementException.
     * @throws IdentityOAuthAdminException            IdentityOAuthAdminException.
     */
    private void initiatePortals()
            throws IdentityApplicationManagementException, IdentityOAuthAdminException, RegistryException,
            UserStoreException {

        ApplicationManagementService applicationMgtService = OAuth2ServiceComponentHolder.getApplicationMgtService();
        OAuthAdminService oAuthAdminService = new OAuthAdminService();

        UserRealm userRealm = OAuth2ServiceComponentHolder.getRegistryService().getUserRealm(SUPER_TENANT_ID);
        String adminUsername = userRealm.getRealmConfiguration().getAdminUserName();

        if (applicationMgtService.getApplicationExcludingFileBasedSPs(USER_PORTAL_APP_NAME, SUPER_TENANT_DOMAIN_NAME)
                == null) {
            // Initiate user-portal
            String userPortalConsumerSecret = OAuthUtil.getRandomNumber();
            createOAuth2Application(oAuthAdminService, USER_PORTAL_APP_NAME, USER_PORTAL_PATH, USER_PORTAL_CONSUMER_KEY,
                    userPortalConsumerSecret, adminUsername);
            createApplication(applicationMgtService, USER_PORTAL_APP_NAME, adminUsername, USER_PORTAL_APP_DESCRIPTION,
                    USER_PORTAL_CONSUMER_KEY, userPortalConsumerSecret);
        }
    }

    /**
     * Create portal application.
     *
     * @param applicationMgtService Application management service instant.
     * @param appName               Application name.
     * @param appOwner              Application owner.
     * @param appDescription        Application description.
     * @param consumerKey           Consumer key.
     * @param consumerSecret        Consumer secret.
     * @throws IdentityApplicationManagementException IdentityApplicationManagementException.
     */
    private void createApplication(ApplicationManagementService applicationMgtService, String appName, String appOwner,
            String appDescription, String consumerKey, String consumerSecret)
            throws IdentityApplicationManagementException {

        ServiceProvider serviceProvider = new ServiceProvider();
        serviceProvider.setApplicationName(appName);
        serviceProvider.setDescription(appDescription);
        applicationMgtService.createApplicationWithTemplate(serviceProvider, SUPER_TENANT_DOMAIN_NAME, appOwner, null);

        InboundAuthenticationRequestConfig inboundAuthenticationRequestConfig = new InboundAuthenticationRequestConfig();
        inboundAuthenticationRequestConfig.setInboundAuthKey(consumerKey);
        inboundAuthenticationRequestConfig.setInboundAuthType(INBOUND_AUTH2_TYPE);
        Property property = new Property();
        property.setName("oauthConsumerSecret");
        property.setValue(consumerSecret);
        Property[] properties = { property };
        inboundAuthenticationRequestConfig.setProperties(properties);

        serviceProvider = applicationMgtService
                .getApplicationExcludingFileBasedSPs(appName, SUPER_TENANT_DOMAIN_NAME);
        InboundAuthenticationConfig inboundAuthenticationConfig = serviceProvider.getInboundAuthenticationConfig();

        List<InboundAuthenticationRequestConfig> inboundAuthenticationRequestConfigs = new ArrayList<>();
        if (inboundAuthenticationConfig.getInboundAuthenticationRequestConfigs() != null
                && inboundAuthenticationConfig.getInboundAuthenticationRequestConfigs().length > 0) {
            inboundAuthenticationRequestConfigs
                    .addAll(Arrays.asList(inboundAuthenticationConfig.getInboundAuthenticationRequestConfigs()));
        }
        inboundAuthenticationRequestConfigs.add(inboundAuthenticationRequestConfig);
        inboundAuthenticationConfig.setInboundAuthenticationRequestConfigs(
                inboundAuthenticationRequestConfigs.toArray(new InboundAuthenticationRequestConfig[0]));

        applicationMgtService
                .updateApplication(serviceProvider, SUPER_TENANT_DOMAIN_NAME, appOwner);
    }

    /**
     * Create OAuth2 application.
     *
     * @param oAuthAdminService OAuthAdminService instance.
     * @param applicationName   Application name.
     * @param portalPath        Portal path.
     * @param consumerKey       Consumer key.
     * @throws IdentityOAuthAdminException IdentityOAuthAdminException.
     */
    private void createOAuth2Application(OAuthAdminService oAuthAdminService, String applicationName, String portalPath,
            String consumerKey, String consumerSecret, String appOwner) throws IdentityOAuthAdminException {

        OAuthConsumerAppDTO oAuthConsumerAppDTO = new OAuthConsumerAppDTO();
        oAuthConsumerAppDTO.setApplicationName(applicationName);
        oAuthConsumerAppDTO.setOAuthVersion(VERSION_2);
        oAuthConsumerAppDTO.setOauthConsumerKey(consumerKey);
        oAuthConsumerAppDTO.setOauthConsumerSecret(consumerSecret);
        oAuthConsumerAppDTO.setCallbackUrl(IdentityUtil.getServerURL(portalPath, false, true));
        oAuthConsumerAppDTO.setBypassClientCredentials(true);
        oAuthConsumerAppDTO.setGrantTypes(AUTHORIZATION_CODE + " " + REFRESH_TOKEN);

        try {
            PrivilegedCarbonContext.startTenantFlow();
            PrivilegedCarbonContext privilegedCarbonContext = PrivilegedCarbonContext.getThreadLocalCarbonContext();
            privilegedCarbonContext.setTenantId(SUPER_TENANT_ID);
            privilegedCarbonContext.setTenantDomain(SUPER_TENANT_DOMAIN_NAME);
            privilegedCarbonContext.setUsername(appOwner);
            oAuthAdminService.registerOAuthApplicationData(oAuthConsumerAppDTO);
        } finally {
            PrivilegedCarbonContext.endTenantFlow();
        }
    }
}
