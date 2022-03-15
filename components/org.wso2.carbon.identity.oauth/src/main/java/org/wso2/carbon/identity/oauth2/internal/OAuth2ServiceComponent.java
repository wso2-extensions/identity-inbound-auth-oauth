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

import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.impl.builder.StAXOMBuilder;
import org.apache.commons.lang.StringUtils;
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
import org.wso2.carbon.identity.application.authentication.framework.AuthenticationDataPublisher;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticationMethodNameTranslator;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.application.mgt.listener.ApplicationMgtListener;
import org.wso2.carbon.identity.core.util.IdentityCoreInitializedEvent;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.token.bindings.TokenBinderInfo;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dto.ScopeDTO;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.OAuth2ScopeService;
import org.wso2.carbon.identity.oauth2.OAuth2Service;
import org.wso2.carbon.identity.oauth2.OAuth2TokenValidationService;
import org.wso2.carbon.identity.oauth2.bean.Scope;
import org.wso2.carbon.identity.oauth2.bean.ScopeBinding;
import org.wso2.carbon.identity.oauth2.client.authentication.BasicAuthClientAuthenticator;
import org.wso2.carbon.identity.oauth2.client.authentication.OAuthClientAuthenticator;
import org.wso2.carbon.identity.oauth2.client.authentication.OAuthClientAuthnService;
import org.wso2.carbon.identity.oauth2.client.authentication.PublicClientAuthenticator;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.device.api.DeviceAuthService;
import org.wso2.carbon.identity.oauth2.device.api.DeviceAuthServiceImpl;
import org.wso2.carbon.identity.oauth2.keyidprovider.DefaultKeyIDProviderImpl;
import org.wso2.carbon.identity.oauth2.keyidprovider.KeyIDProvider;
import org.wso2.carbon.identity.oauth2.listener.TenantCreationEventListener;
import org.wso2.carbon.identity.oauth2.token.bindings.TokenBinder;
import org.wso2.carbon.identity.oauth2.token.bindings.handlers.TokenBindingExpiryEventHandler;
import org.wso2.carbon.identity.oauth2.token.bindings.impl.CookieBasedTokenBinder;
import org.wso2.carbon.identity.oauth2.token.bindings.impl.DeviceFlowTokenBinder;
import org.wso2.carbon.identity.oauth2.token.bindings.impl.SSOSessionBasedTokenBinder;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.oauth2.validators.scope.ScopeValidator;
import org.wso2.carbon.identity.openidconnect.OpenIDConnectClaimFilter;
import org.wso2.carbon.identity.openidconnect.OpenIDConnectClaimFilterImpl;
import org.wso2.carbon.identity.openidconnect.dao.ScopeClaimMappingDAO;
import org.wso2.carbon.identity.openidconnect.dao.ScopeClaimMappingDAOImpl;
import org.wso2.carbon.identity.user.store.configuration.listener.UserStoreConfigListener;
import org.wso2.carbon.idp.mgt.IdpManager;
import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.stratos.common.listeners.TenantMgtListener;
import org.wso2.carbon.utils.CarbonUtils;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;

import static org.wso2.carbon.identity.oauth2.Oauth2ScopeConstants.PERMISSIONS_BINDING_TYPE;
import static org.wso2.carbon.identity.oauth2.device.constants.Constants.DEVICE_FLOW_GRANT_TYPE;
import static org.wso2.carbon.identity.oauth2.util.OAuth2Util.checkAudienceEnabled;
import static org.wso2.carbon.identity.oauth2.util.OAuth2Util.checkIDPIdColumnAvailable;

/**
 * OAuth 2 OSGi service component.
 */
@Component(
        name = "identity.oauth2.component",
        immediate = true
)
public class OAuth2ServiceComponent {

    private static final Log log = LogFactory.getLog(OAuth2ServiceComponent.class);
    private static final String IDENTITY_PATH = "identity";
    public static final String NAME = "name";
    public static final String ID = "id";
    private static final String DISPLAY_NAME = "displayName";
    private static final String DESCRIPTION = "description";
    private static final String PERMISSION = "Permission";
    private static final String CLAIM = "Claim";
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
            if (OAuth2ServiceComponentHolder.getInstance().getScopeClaimMappingDAO() == null) {
                OAuth2ServiceComponentHolder.getInstance()
                        .setScopeClaimMappingDAO(new ScopeClaimMappingDAOImpl());
            }
            loadScopeConfigFile();
            loadOauthScopeBinding();
            int tenantId = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId();
            boolean isRecordExist = OAuthTokenPersistenceFactory.getInstance().getScopeClaimMappingDAO().
                    hasScopesPopulated(tenantId);
            if (!isRecordExist) {
                OAuth2Util.initiateOIDCScopes(tenantId);
            }
            TenantCreationEventListener scopeTenantMgtListener = new TenantCreationEventListener();
            bundleContext = context.getBundleContext();
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
            // iniating oauth scopes
            OAuth2Util.initiateOAuthScopePermissionsBindings(tenantId);
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

            // Register cookie based access token binder.
            CookieBasedTokenBinder cookieBasedTokenBinder = new CookieBasedTokenBinder();
            bundleContext.registerService(TokenBinderInfo.class.getName(), cookieBasedTokenBinder, null);

            // SSO session based access token binder.
            SSOSessionBasedTokenBinder ssoSessionBasedTokenBinder = new SSOSessionBasedTokenBinder();
            bundleContext.registerService(TokenBinderInfo.class.getName(), ssoSessionBasedTokenBinder, null);

            // Device based access token binder only if token binding is enabled.
            if (OAuth2Util.getSupportedGrantTypes().contains(DEVICE_FLOW_GRANT_TYPE)) {
                DeviceFlowTokenBinder deviceFlowTokenBinder = new DeviceFlowTokenBinder();
                bundleContext.registerService(TokenBinderInfo.class.getName(), deviceFlowTokenBinder, null);
            }

            if (log.isDebugEnabled()) {
                log.debug("Identity OAuth bundle is activated");
            }

            if (OAuth2ServiceComponentHolder.getKeyIDProvider() == null) {
                KeyIDProvider defaultKeyIDProvider = new DefaultKeyIDProviderImpl();
                OAuth2ServiceComponentHolder.setKeyIDProvider(defaultKeyIDProvider);
                if (log.isDebugEnabled()) {
                    log.debug("Key ID Provider " + DefaultKeyIDProviderImpl.class.getSimpleName() +
                            " registered as the default Key ID Provider implementation.");
                }
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

            // PKCE enabled by default.
            OAuth2ServiceComponentHolder.setPkceEnabled(true);

            // Register device auth service.
            ServiceRegistration deviceAuthService = bundleContext.registerService(DeviceAuthService.class.getName(),
                    new DeviceAuthServiceImpl(), null);
            if (deviceAuthService != null) {
                if (log.isDebugEnabled()) {
                    log.debug("DeviceAuthService registered.");
                }
            } else {
                log.error("DeviceAuthService could not be registered.");
            }

            // Register the default OpenIDConnect claim filter
            bundleContext.registerService(OpenIDConnectClaimFilter.class, new OpenIDConnectClaimFilterImpl(), null);
            if (log.isDebugEnabled()) {
                log.debug("Default OpenIDConnect Claim filter registered successfully.");
            }

            bundleContext.registerService(AbstractEventHandler.class.getName(), new TokenBindingExpiryEventHandler(),
                    null);
            if (log.isDebugEnabled()) {
                log.debug("TokenBindingExpiryEventHandler is successfully registered.");
            }

            // Registering OAuth2Service as a OSGIService
            bundleContext.registerService(OAuth2Service.class.getName(), new OAuth2Service(), null);
            // Registering OAuth2ScopeService as a OSGIService
            bundleContext.registerService(OAuth2ScopeService.class.getName(), new OAuth2ScopeService(), null);
            // Note : DO NOT add any activation related code below this point,
            // to make sure the server doesn't start up if any activation failures occur

        } catch (Throwable e) {
            String errMsg = "Error while activating OAuth2ServiceComponent.";
            log.error(errMsg, e);
            throw new RuntimeException(errMsg, e);
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

    @Reference(name = "token.binding.service",
               service = TokenBinderInfo.class,
               cardinality = ReferenceCardinality.MULTIPLE,
               policy = ReferencePolicy.DYNAMIC,
               unbind = "unsetTokenBinderInfo")
    protected void setTokenBinderInfo(TokenBinderInfo tokenBinderInfo) {

        if (log.isDebugEnabled()) {
            log.debug("Setting the token binder for: " + tokenBinderInfo.getBindingType());
        }
        if (tokenBinderInfo instanceof TokenBinder) {
            OAuth2ServiceComponentHolder.getInstance().addTokenBinder((TokenBinder) tokenBinderInfo);
        }
    }

    protected void unsetTokenBinderInfo(TokenBinderInfo tokenBinderInfo) {

        if (log.isDebugEnabled()) {
            log.debug("Un-setting the token binder for: " + tokenBinderInfo.getBindingType());
        }
        if (tokenBinderInfo instanceof TokenBinder) {
            OAuth2ServiceComponentHolder.getInstance().removeTokenBinder((TokenBinder) tokenBinderInfo);
        }
    }

    @Reference(
            name = "framework.authentication.data.publisher",
            service = AuthenticationDataPublisher.class,
            cardinality = ReferenceCardinality.MULTIPLE,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetAuthenticationDataPublisher"
    )
    protected void setAuthenticationDataPublisher(AuthenticationDataPublisher dataPublisher) {

        if (FrameworkConstants.AnalyticsAttributes.AUTHN_DATA_PUBLISHER_PROXY.equalsIgnoreCase(dataPublisher.
                getName()) && dataPublisher.isEnabled(null)) {
            OAuth2ServiceComponentHolder.setAuthenticationDataPublisherProxy(dataPublisher);
        }
    }

    protected void unsetAuthenticationDataPublisher(AuthenticationDataPublisher dataPublisher) {

        if (FrameworkConstants.AnalyticsAttributes.AUTHN_DATA_PUBLISHER_PROXY.equalsIgnoreCase(dataPublisher.
                getName()) && dataPublisher.isEnabled(null)) {
            OAuth2ServiceComponentHolder.setAuthenticationDataPublisherProxy(null);
        }
    }

    @Reference(
            name = "keyid.provider.component",
            service = KeyIDProvider.class,
            cardinality = ReferenceCardinality.MULTIPLE,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetKeyIDProvider"
    )
    protected void setKeyIDProvider(KeyIDProvider keyIDProvider) {

        KeyIDProvider oldKeyIDProvider = OAuth2ServiceComponentHolder.getKeyIDProvider();
        if (oldKeyIDProvider == null || oldKeyIDProvider.getClass().getSimpleName().
                equals(DefaultKeyIDProviderImpl.class.getSimpleName())) {

            OAuth2ServiceComponentHolder.setKeyIDProvider(keyIDProvider);
            if (log.isDebugEnabled()) {
                log.debug("Custom Key ID Provider: " + keyIDProvider.getClass().getSimpleName() +
                        "Registered replacing the default Key ID provider implementation.");
            }
        } else {
            log.warn("Key ID Provider: " + keyIDProvider.getClass().getSimpleName() +
                    " not registered since a custom Key ID Provider already exists in the placeholder.");
        }

    }

    protected void unsetKeyIDProvider(KeyIDProvider keyIDProvider) {

    }

    @Reference(
            name = "scope.validator.service",
            service = ScopeValidator.class,
            cardinality = ReferenceCardinality.MULTIPLE,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "removeScopeValidatorService"
    )
    protected void addScopeValidatorService(ScopeValidator scopeValidator) {

        if (log.isDebugEnabled()) {
            log.debug("Adding the Scope validator Service : " + scopeValidator.getName());
        }
        OAuthComponentServiceHolder.getInstance().addScopeValidator(scopeValidator);
    }

    protected void removeScopeValidatorService(ScopeValidator scopeValidator) {

        if (log.isDebugEnabled()) {
            log.debug("Removing the Scope validator Service : " + scopeValidator.getName());
        }
        OAuthComponentServiceHolder.getInstance().removeScopeValidator(scopeValidator);
    }

    @Reference(
            name = "IdentityProviderManager",
            service = org.wso2.carbon.idp.mgt.IdpManager.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetIdpManager")
    protected void setIdpManager(IdpManager idpManager) {

        OAuth2ServiceComponentHolder.getInstance().setIdpManager(idpManager);
    }

    protected void unsetIdpManager(IdpManager idpManager) {

        OAuth2ServiceComponentHolder.getInstance().setIdpManager(null);
    }

    @Reference(
            name = "scope.claim.mapping.dao",
            service = ScopeClaimMappingDAO.class,
            cardinality = ReferenceCardinality.OPTIONAL,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetScopeClaimMappingDAO"
    )
    protected void setScopeClaimMappingDAO(ScopeClaimMappingDAO scopeClaimMappingDAO) {

        ScopeClaimMappingDAO existingScopeClaimMappingDAO = OAuth2ServiceComponentHolder.getInstance()
                .getScopeClaimMappingDAO();
        if (existingScopeClaimMappingDAO != null) {
            log.warn("Scope Claim DAO implementation " + existingScopeClaimMappingDAO.getClass().getName() +
                            " is registered already and PersistenceFactory is created." +
                            " So DAO Impl : " + scopeClaimMappingDAO.getClass().getName() + " will not be registered");
        } else {
            OAuth2ServiceComponentHolder.getInstance().setScopeClaimMappingDAO(scopeClaimMappingDAO);
            if (log.isDebugEnabled()) {
                log.debug("Scope Claim DAO implementation got registered: " +
                        scopeClaimMappingDAO.getClass().getName());
            }
        }
    }

    protected void unsetScopeClaimMappingDAO(ScopeClaimMappingDAO scopeClaimMappingDAO) {

        OAuth2ServiceComponentHolder.getInstance().setScopeClaimMappingDAO(new ScopeClaimMappingDAOImpl());
        if (log.isDebugEnabled()) {
            log.debug("Scope Claim DAO implementation got removed: " + scopeClaimMappingDAO.getClass().getName());
        }
    }

    private static void loadScopeConfigFile() {

        List<ScopeDTO> listOIDCScopesClaims = new ArrayList<>();
        String configDirPath = CarbonUtils.getCarbonConfigDirPath();
        String confXml =
                Paths.get(configDirPath, IDENTITY_PATH, OAuthConstants.OIDC_SCOPE_CONFIG_PATH).toString();
        File configFile = new File(confXml);
        if (!configFile.exists()) {
            log.warn("OIDC scope-claim Configuration File is not present at: " + confXml);
            return;
        }

        XMLStreamReader parser = null;
        try (InputStream stream = new FileInputStream(configFile)) {

            parser = XMLInputFactory.newInstance().createXMLStreamReader(stream);
            StAXOMBuilder builder = new StAXOMBuilder(parser);
            OMElement documentElement = builder.getDocumentElement();
            Iterator iterator = documentElement.getChildElements();
            while (iterator.hasNext()) {
                ScopeDTO scope = new ScopeDTO();
                OMElement omElement = (OMElement) iterator.next();
                String configType = omElement.getAttributeValue(new QName(ID));
                scope.setName(configType);

                String displayName = omElement.getAttributeValue(new QName(DISPLAY_NAME));
                if (StringUtils.isNotEmpty(displayName)) {
                    scope.setDisplayName(displayName);
                } else {
                    scope.setDisplayName(configType);
                }

                String description = omElement.getAttributeValue(new QName(DESCRIPTION));
                if (StringUtils.isNotEmpty(description)) {
                    scope.setDescription(description);
                }

                scope.setClaim(loadClaimConfig(omElement));
                listOIDCScopesClaims.add(scope);
            }
        } catch (XMLStreamException e) {
            log.warn("Error while streaming OIDC scope config.", e);
        } catch (IOException e) {
            log.warn("Error while loading OIDC scope config.", e);
        } finally {
            try {
                if (parser != null) {
                    parser.close();
                }
            } catch (XMLStreamException e) {
                log.error("Error while closing XML stream", e);
            }
        }
        OAuth2ServiceComponentHolder.getInstance().setOIDCScopesClaims(listOIDCScopesClaims);
    }

    private static String[] loadClaimConfig(OMElement configElement) {

        StringBuilder claimConfig = new StringBuilder();
        Iterator it = configElement.getChildElements();
        while (it.hasNext()) {
            OMElement element = (OMElement) it.next();
            if (CLAIM.equals(element.getLocalName())) {
                String commaSeparatedClaimNames = element.getText();
                if (StringUtils.isNotBlank(commaSeparatedClaimNames)) {
                    claimConfig.append(commaSeparatedClaimNames.trim());
                }
            }
        }

        String[] claim;
        if (claimConfig.length() > 0) {
            claim = claimConfig.toString().split(",");
        } else {
            claim = new String[0];
        }
        return claim;
    }

    private static void loadOauthScopeBinding() {

        List<Scope> scopes = new ArrayList<>();
        String configDirPath = CarbonUtils.getCarbonConfigDirPath();
        String confXml = Paths.get(configDirPath, IDENTITY_PATH, OAuthConstants.OAUTH_SCOPE_BINDING_PATH).toString();
        File configFile = new File(confXml);
        if (!configFile.exists()) {
            log.warn("OAuth scope binding File is not present at: " + confXml);
            return;
        }

        XMLStreamReader parser = null;
        try (InputStream stream = new FileInputStream(configFile)) {

            parser = XMLInputFactory.newInstance()
                    .createXMLStreamReader(stream);
            StAXOMBuilder builder = new StAXOMBuilder(parser);
            OMElement documentElement = builder.getDocumentElement();
            Iterator iterator = documentElement.getChildElements();
            while (iterator.hasNext()) {
                OMElement omElement = (OMElement) iterator.next();
                String scopeName = omElement.getAttributeValue(new QName(NAME));
                String displayName = omElement.getAttributeValue(new QName(DISPLAY_NAME));
                String description = omElement.getAttributeValue(new QName(DESCRIPTION));
                List<String> bindingPermissions = loadScopePermissions(omElement);
                ScopeBinding scopeBinding = new ScopeBinding(PERMISSIONS_BINDING_TYPE, bindingPermissions);
                List<ScopeBinding> scopeBindings = new ArrayList<>();
                scopeBindings.add(scopeBinding);
                Scope scope = new Scope(scopeName, displayName, scopeBindings, description);
                scopes.add(scope);
            }
        } catch (XMLStreamException e) {
            log.warn("Error while streaming oauth-scope-bindings config.", e);
        } catch (IOException e) {
            log.warn("Error while loading oauth-scope-bindings config.", e);
        } finally {
            try {
                if (parser != null) {
                    parser.close();
                }
            } catch (XMLStreamException e) {
                log.error("Error while closing XML stream", e);
            }
        }
        OAuth2ServiceComponentHolder.getInstance().setOauthScopeBinding(scopes);
    }

    private static List<String> loadScopePermissions(OMElement configElement) {

        List<String> permissions = new ArrayList<>();
        Iterator it = configElement.getChildElements();
        while (it.hasNext()) {
            OMElement element = (OMElement) it.next();
            Iterator permissionIterator = element.getChildElements();
            while (permissionIterator.hasNext()) {
                OMElement permissionElement = (OMElement) permissionIterator.next();
                if (PERMISSION.equals(permissionElement.getLocalName())) {
                    String permission = permissionElement.getText();
                    permissions.add(permission);
                }
            }
        }
        return permissions;
    }
}
