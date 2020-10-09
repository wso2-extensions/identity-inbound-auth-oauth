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
import org.wso2.carbon.identity.application.authentication.framework.AuthenticationDataPublisher;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticationMethodNameTranslator;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.application.mgt.listener.ApplicationMgtListener;
import org.wso2.carbon.identity.core.util.IdentityCoreInitializedEvent;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.carbon.identity.oauth.common.token.bindings.TokenBinderInfo;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.OAuth2ScopeService;
import org.wso2.carbon.identity.oauth2.OAuth2Service;
import org.wso2.carbon.identity.oauth2.OAuth2TokenValidationService;
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
import org.wso2.carbon.identity.oauth2.token.bindings.impl.SSOSessionBasedTokenBinder;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.oauth2.validators.scope.ScopeValidator;
import org.wso2.carbon.identity.openidconnect.OpenIDConnectClaimFilter;
import org.wso2.carbon.identity.openidconnect.OpenIDConnectClaimFilterImpl;
import org.wso2.carbon.identity.user.store.configuration.listener.UserStoreConfigListener;
import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.stratos.common.listeners.TenantMgtListener;

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

}
