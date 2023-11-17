/*
 * Copyright (c) 2013-2023, WSO2 LLC. (http://www.wso2.com).
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
import org.wso2.carbon.identity.api.resource.mgt.APIResourceManager;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticationService;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticationDataPublisher;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticationMethodNameTranslator;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.application.mgt.AuthorizedAPIManagementService;
import org.wso2.carbon.identity.application.mgt.listener.ApplicationMgtListener;
import org.wso2.carbon.identity.consent.server.configs.mgt.services.ConsentServerConfigsManagementService;
import org.wso2.carbon.identity.core.SAMLSSOServiceProviderManager;
import org.wso2.carbon.identity.core.util.IdentityCoreInitializedEvent;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.carbon.identity.event.services.IdentityEventService;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.token.bindings.TokenBinderInfo;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dto.ScopeDTO;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth.tokenprocessor.OAuth2RevocationProcessor;
import org.wso2.carbon.identity.oauth.tokenprocessor.RefreshTokenGrantProcessor;
import org.wso2.carbon.identity.oauth.tokenprocessor.TokenProvider;
import org.wso2.carbon.identity.oauth2.OAuth2ScopeService;
import org.wso2.carbon.identity.oauth2.OAuth2Service;
import org.wso2.carbon.identity.oauth2.OAuth2TokenValidationService;
import org.wso2.carbon.identity.oauth2.OAuthAuthorizationRequestBuilder;
import org.wso2.carbon.identity.oauth2.authz.validators.ResponseTypeRequestValidator;
import org.wso2.carbon.identity.oauth2.bean.Scope;
import org.wso2.carbon.identity.oauth2.bean.ScopeBinding;
import org.wso2.carbon.identity.oauth2.client.authentication.BasicAuthClientAuthenticator;
import org.wso2.carbon.identity.oauth2.client.authentication.OAuthClientAuthenticator;
import org.wso2.carbon.identity.oauth2.client.authentication.OAuthClientAuthnService;
import org.wso2.carbon.identity.oauth2.client.authentication.PublicClientAuthenticator;
import org.wso2.carbon.identity.oauth2.dao.AccessTokenDAO;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.dao.TokenManagementDAO;
import org.wso2.carbon.identity.oauth2.device.api.DeviceAuthService;
import org.wso2.carbon.identity.oauth2.device.api.DeviceAuthServiceImpl;
import org.wso2.carbon.identity.oauth2.device.response.DeviceFlowResponseTypeRequestValidator;
import org.wso2.carbon.identity.oauth2.keyidprovider.DefaultKeyIDProviderImpl;
import org.wso2.carbon.identity.oauth2.keyidprovider.KeyIDProvider;
import org.wso2.carbon.identity.oauth2.listener.TenantCreationEventListener;
import org.wso2.carbon.identity.oauth2.scopeservice.APIResourceBasedScopeMetadataService;
import org.wso2.carbon.identity.oauth2.scopeservice.ScopeMetadataService;
import org.wso2.carbon.identity.oauth2.token.bindings.TokenBinder;
import org.wso2.carbon.identity.oauth2.token.bindings.handlers.TokenBindingExpiryEventHandler;
import org.wso2.carbon.identity.oauth2.token.bindings.impl.CertificateBasedTokenBinder;
import org.wso2.carbon.identity.oauth2.token.bindings.impl.CookieBasedTokenBinder;
import org.wso2.carbon.identity.oauth2.token.bindings.impl.DeviceFlowTokenBinder;
import org.wso2.carbon.identity.oauth2.token.bindings.impl.SSOSessionBasedTokenBinder;
import org.wso2.carbon.identity.oauth2.token.handlers.claims.JWTAccessTokenClaimProvider;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.oauth2.validators.scope.RoleBasedScopeIssuer;
import org.wso2.carbon.identity.oauth2.validators.scope.ScopeValidator;
import org.wso2.carbon.identity.oauth2.validators.validationhandler.ScopeValidationHandler;
import org.wso2.carbon.identity.oauth2.validators.validationhandler.impl.M2MScopeValidationHandler;
import org.wso2.carbon.identity.oauth2.validators.validationhandler.impl.NoPolicyScopeValidationHandler;
import org.wso2.carbon.identity.oauth2.validators.validationhandler.impl.RoleBasedScopeValidationHandler;
import org.wso2.carbon.identity.openidconnect.OpenIDConnectClaimFilter;
import org.wso2.carbon.identity.openidconnect.OpenIDConnectClaimFilterImpl;
import org.wso2.carbon.identity.openidconnect.dao.ScopeClaimMappingDAO;
import org.wso2.carbon.identity.openidconnect.dao.ScopeClaimMappingDAOImpl;
import org.wso2.carbon.identity.organization.management.role.management.service.RoleManager;
import org.wso2.carbon.identity.organization.management.service.OrganizationManagementInitialize;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.identity.organization.management.service.OrganizationUserResidentResolverService;
import org.wso2.carbon.identity.role.v2.mgt.core.RoleManagementService;
import org.wso2.carbon.identity.user.store.configuration.listener.UserStoreConfigListener;
import org.wso2.carbon.idp.mgt.IdpManager;
import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.stratos.common.listeners.TenantMgtListener;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.CarbonUtils;
import org.wso2.carbon.utils.ConfigurationContextService;

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
import static org.wso2.carbon.identity.oauth2.util.OAuth2Util.checkConsentedTokenColumnAvailable;
import static org.wso2.carbon.identity.oauth2.util.OAuth2Util.checkIDPIdColumnAvailable;
import static org.wso2.carbon.identity.oauth2.util.OAuth2Util.getJWTRenewWithoutRevokeAllowedGrantTypes;
import static org.wso2.carbon.identity.oauth2.util.OAuth2Util.isAccessTokenExtendedTableExist;

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

    @Reference(
            name = "oauth.authorization.request.builder.service",
            service = OAuthAuthorizationRequestBuilder.class,
            cardinality = ReferenceCardinality.MULTIPLE,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "removeAuthorizationRequestBuilderService"
    )
    protected void addAuthorizationRequestBuilderService(
            OAuthAuthorizationRequestBuilder oAuthAuthorizationRequestBuilder) {

        if (log.isDebugEnabled()) {
            log.debug("Adding the oauth authorization request builder service : "
                    + oAuthAuthorizationRequestBuilder.getName());
        }
        OAuth2ServiceComponentHolder.getInstance().addAuthorizationRequestBuilder(oAuthAuthorizationRequestBuilder);
    }

    protected void removeAuthorizationRequestBuilderService(
            OAuthAuthorizationRequestBuilder oAuthAuthorizationRequestBuilder) {

        if (log.isDebugEnabled()) {
            log.debug("Removing the oauth authorization request builder service : "
                    + oAuthAuthorizationRequestBuilder.getName());
        }
        OAuth2ServiceComponentHolder.getInstance().removeAuthorizationRequestBuilder(oAuthAuthorizationRequestBuilder);
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
            // Check if server compliant with the client ID tenant unification.
            if (!OAuth2Util.isCompliantWithClientIDTenantUnification()) {
                throw new RuntimeException("The unique key constraint in the IDN_OAUTH_CONSUMER_APPS table is not " +
                        "compatible with the server configs on tenant qualified URLs and/ or tenanted sessions.");
            }

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

            /* Certificate based token binder will be enabled only if certificate binding is not being performed in the
               MTLS authenticator. By default, the certificate binding type will be enabled. */
            if (Boolean.parseBoolean(IdentityUtil
                    .getProperty(OAuthConstants.ENABLE_TLS_CERT_BOUND_ACCESS_TOKENS_VIA_BINDING_TYPE))) {
                CertificateBasedTokenBinder certificateBasedTokenBinder = new CertificateBasedTokenBinder();
                bundleContext.registerService(TokenBinderInfo.class.getName(), certificateBasedTokenBinder, null);
            }

            bundleContext.registerService(ResponseTypeRequestValidator.class.getName(),
                    new DeviceFlowResponseTypeRequestValidator(), null);

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

            // Read and store the allowed grant types for JWT renew without revoke in OAuth2ServiceComponentHolder.
            OAuth2ServiceComponentHolder.setJwtRenewWithoutRevokeAllowedGrantTypes(
                    getJWTRenewWithoutRevokeAllowedGrantTypes());

            OAuth2ServiceComponentHolder.
                    setResponseModeProviders(OAuthServerConfiguration.getInstance().getSupportedResponseModes());
            OAuth2ServiceComponentHolder.
                    setDefaultResponseModeProvider(OAuthServerConfiguration.getInstance()
                            .getDefaultResponseModeProvider());

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
            OAuth2ScopeService oAuth2ScopeService = new OAuth2ScopeService();
            // Registering OAuth2ScopeService as a OSGIService
            bundleContext.registerService(OAuth2ScopeService.class.getName(), oAuth2ScopeService, null);
            // Registering OAuth2ScopeService under ScopeService interface.
            bundleContext.registerService(ScopeMetadataService.class, oAuth2ScopeService, null);

            // Registering API Resource based scope metadata service under ScopeService interface.
            bundleContext.registerService(ScopeMetadataService.class, new APIResourceBasedScopeMetadataService(), null);

            bundleContext.registerService(ScopeValidationHandler.class, new RoleBasedScopeValidationHandler(), null);
            bundleContext.registerService(ScopeValidationHandler.class, new NoPolicyScopeValidationHandler(), null);
            bundleContext.registerService(ScopeValidationHandler.class, new M2MScopeValidationHandler(), null);

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

        if (isAccessTokenExtendedTableExist()) {
            log.debug("IDN_OAUTH2_ACCESS_TOKEN_EXTENDED table is available Setting " +
                    "isAccessTokenExtendedTableExist to true.");
            OAuth2ServiceComponentHolder.setTokenExtendedTableExist(true);
        }

        boolean isConsentedTokenColumnAvailable = checkConsentedTokenColumnAvailable();
        OAuth2ServiceComponentHolder.setConsentedTokenColumnEnabled(isConsentedTokenColumnAvailable);
        if (log.isDebugEnabled()) {
            if (isConsentedTokenColumnAvailable) {
                log.debug("CONSENTED_TOKEN column is available in IDN_OAUTH2_ACCESS_TOKEN table. Hence setting " +
                        "consentedColumnAvailable to true.");
            } else {
                log.debug("CONSENTED_TOKEN column is not available in IDN_OAUTH2_ACCESS_TOKEN table. Hence " +
                        "setting consentedColumnAvailable to false.");
            }
        }
        if (OAuthServerConfiguration.getInstance().isGlobalRbacScopeIssuerEnabled()) {
            bundleContext.registerService(ScopeValidator.class, new RoleBasedScopeIssuer(), null);
        }
        boolean restrictUnassignedScopes = Boolean.parseBoolean(System.getProperty(
                OAuthConstants.RESTRICT_UNASSIGNED_SCOPES));
        OAuth2ServiceComponentHolder.setRestrictUnassignedScopes(restrictUnassignedScopes);
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

    @Reference(name = "response.type.request.validator",
            service = ResponseTypeRequestValidator.class,
            cardinality = ReferenceCardinality.MULTIPLE,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetResponseTypeRequestValidator")
    protected void setResponseTypeRequestValidator(ResponseTypeRequestValidator validator) {

        OAuth2ServiceComponentHolder.getInstance().addResponseTypeRequestValidator(validator);
        if (log.isDebugEnabled()) {
            log.debug("Setting the response type request validator for: " + validator.getResponseType());
        }
    }

    protected void unsetResponseTypeRequestValidator(ResponseTypeRequestValidator validator) {

        OAuth2ServiceComponentHolder.getInstance().removeResponseTypeRequestValidator(validator);
        if (log.isDebugEnabled()) {
            log.debug("Un-setting the response type request validator for: " + validator.getResponseType());
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
            name = "scope.validator.handler",
            service = ScopeValidationHandler.class,
            cardinality = ReferenceCardinality.MULTIPLE,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "removeScopeValidationHandler"
    )
    protected void addScopeValidationHandler(ScopeValidationHandler scopeValidationHandler) {

        if (log.isDebugEnabled()) {
            log.debug("Adding the Scope validation handler Service : " + scopeValidationHandler.getName());
        }
        OAuthComponentServiceHolder.getInstance().addScopeValidationHandler(scopeValidationHandler);
    }

    protected void removeScopeValidationHandler(ScopeValidationHandler scopeValidationHandler) {

        if (log.isDebugEnabled()) {
            log.debug("Removing the Scope validator Service : " + scopeValidationHandler.getName());
        }
        OAuthComponentServiceHolder.getInstance().removeScopeValidationHandler(scopeValidationHandler);
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

    @Reference(
            name = "carbon.organization.management.role.management.component",
            service = RoleManager.class,
            cardinality = ReferenceCardinality.OPTIONAL,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetOrganizationRoleManager"
    )
    protected void setOrganizationRoleManager(RoleManager roleManager) {

        if (log.isDebugEnabled()) {
            log.debug("Setting organization role management service");
        }
        OAuth2ServiceComponentHolder.setRoleManager(roleManager);
    }

    protected void unsetOrganizationRoleManager(RoleManager roleManager) {

        OAuth2ServiceComponentHolder.setRoleManager(null);
        if (log.isDebugEnabled()) {
            log.debug("Unset organization role management service.");
        }
    }

    @Reference(
            name = "organization.user.resident.resolver.service",
            service = OrganizationUserResidentResolverService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetOrganizationUserResidentResolverService"
    )
    protected void setOrganizationUserResidentResolverService(
            OrganizationUserResidentResolverService organizationUserResidentResolverService) {

        if (log.isDebugEnabled()) {
            log.debug("Setting the organization user resident resolver service.");
        }
        OAuth2ServiceComponentHolder.setOrganizationUserResidentResolverService(
                organizationUserResidentResolverService);
    }

    protected void unsetOrganizationUserResidentResolverService(
            OrganizationUserResidentResolverService organizationUserResidentResolverService) {

        if (log.isDebugEnabled()) {
            log.debug("Unset organization user resident resolver service.");
        }
        OAuth2ServiceComponentHolder.setOrganizationUserResidentResolverService(null);
    }

    /**
     * Sets the token provider.
     *
     * @param tokenProvider TokenProvider
     */
    @Reference(
            name = "token.provider",
            service = TokenProvider.class,
            cardinality = ReferenceCardinality.OPTIONAL,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetTokenProvider"
    )
    protected void setTokenProvider(TokenProvider tokenProvider) {

        if (log.isDebugEnabled()) {
            log.debug("Setting token provider.");
        }
        OAuth2ServiceComponentHolder.getInstance().setTokenProvider(tokenProvider);
    }

    /**
     * Unsets the token provider.
     *
     * @param tokenProvider TokenProvider
     */
    protected void unsetTokenProvider(TokenProvider tokenProvider) {

        if (log.isDebugEnabled()) {
            log.debug("Unset token provider.");
        }
        OAuth2ServiceComponentHolder.getInstance().setTokenProvider(null);
    }

    /**
     * Sets the refresh token grant processor.
     *
     * @param refreshTokenGrantProcessor RefreshTokenGrantProcessor
     */
    @Reference(
            name = "refreshtoken.grant.processor",
            service = RefreshTokenGrantProcessor.class,
            cardinality = ReferenceCardinality.OPTIONAL,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRefreshTokenGrantProcessor"
    )
    protected void setRefreshTokenGrantProcessor(RefreshTokenGrantProcessor refreshTokenGrantProcessor) {

        if (log.isDebugEnabled()) {
            log.debug("Setting refresh token grant processor.");
        }
        OAuth2ServiceComponentHolder.getInstance().setRefreshTokenGrantProcessor(refreshTokenGrantProcessor);
    }

    /**
     * Unsets the refresh token grant processor.
     *
     * @param refreshTokenGrantProcessor RefreshTokenGrantProcessor
     */
    protected void unsetRefreshTokenGrantProcessor(RefreshTokenGrantProcessor refreshTokenGrantProcessor) {

        if (log.isDebugEnabled()) {
            log.debug("Unset refresh token grant processor.");
        }
        OAuth2ServiceComponentHolder.getInstance().setRefreshTokenGrantProcessor(null);
    }

    /**
     * Sets the access token grant processor.
     *
     * @param accessTokenDAO AccessTokenDAO
     */
    @Reference(
            name = "access.token.dao.service",
            service = AccessTokenDAO.class,
            cardinality = ReferenceCardinality.OPTIONAL,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetAccessTokenDAOService"
    )
    protected void setAccessTokenDAOService(AccessTokenDAO accessTokenDAO) {

        if (log.isDebugEnabled()) {
            log.debug(String.format("Adding the Access Token DAO Service : %s", accessTokenDAO.getClass().getName()));
        }
        OAuthComponentServiceHolder.getInstance().setAccessTokenDAOService(accessTokenDAO);
    }

    /**
     * Unsets the access token grant processor.
     *
     * @param accessTokenDAO   AccessTokenDAO
     */
    protected void unsetAccessTokenDAOService(AccessTokenDAO accessTokenDAO) {

        if (log.isDebugEnabled()) {
            log.debug(String.format("Removing the Access Token DAO Service : %s", accessTokenDAO.getClass().getName()));
        }
        OAuthComponentServiceHolder.getInstance().setAccessTokenDAOService(null);
    }

    /**
     * Sets the access token grant processor.
     *
     * @param tokenMgtDAOService TokenManagementDAO
     */
    @Reference(
            name = "token.management.dao.service",
            service = TokenManagementDAO.class,
            cardinality = ReferenceCardinality.OPTIONAL,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetTokenMgtDAOService"
    )
    protected void setTokenMgtDAOService(TokenManagementDAO tokenMgtDAOService) {

        if (log.isDebugEnabled()) {
            log.debug(String.format("Adding the Token Mgt DAO Service : %s", tokenMgtDAOService.getClass().getName()));
        }
        OAuthComponentServiceHolder.getInstance().setTokenManagementDAOService(tokenMgtDAOService);
    }

    /**
     * Unsets the access token grant processor.
     *
     * @param tokenManagementDAO TokenManagementDAO
     */
    protected void unsetTokenMgtDAOService(TokenManagementDAO tokenManagementDAO) {

        if (log.isDebugEnabled()) {
            log.debug(String.format("Removing the Token Mgt DAO Service : %s",
                    tokenManagementDAO.getClass().getName()));
        }
        OAuthComponentServiceHolder.getInstance().setTokenManagementDAOService(null);
    }


    /**
     * Sets the access token grant processor.
     *
     * @param oAuth2RevocationProcessor OAuth2RevocationProcessor
     */
    @Reference(
            name = "oauth2.revocation.processor",
            service = OAuth2RevocationProcessor.class,
            cardinality = ReferenceCardinality.OPTIONAL,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetOAuth2RevocationProcessor"
    )
    protected void setOAuth2RevocationProcessor(OAuth2RevocationProcessor oAuth2RevocationProcessor) {

        if (log.isDebugEnabled()) {
            log.debug("Setting Oauth2 revocation processor.");
        }
        OAuth2ServiceComponentHolder.getInstance().setRevocationProcessor(oAuth2RevocationProcessor);
    }

    /**
     * Unsets the access token grant processor.
     *
     * @param oAuth2RevocationProcessor OAuth2RevocationProcessor
     */
    protected void unsetOAuth2RevocationProcessor(OAuth2RevocationProcessor oAuth2RevocationProcessor) {

        if (log.isDebugEnabled()) {
            log.debug("Unset Oauth2 revocation processor.");
        }
        OAuth2ServiceComponentHolder.getInstance().setRevocationProcessor(null);
    }

    @Reference(
            name = "organization.mgt.initialize.service",
            service = OrganizationManagementInitialize.class,
            cardinality = ReferenceCardinality.OPTIONAL,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetOrganizationManagementEnablingService"
    )
    protected void setOrganizationManagementEnablingService(
            OrganizationManagementInitialize organizationManagementInitializeService) {

        OAuth2ServiceComponentHolder.getInstance()
                .setOrganizationManagementEnable(organizationManagementInitializeService);
    }

    protected void unsetOrganizationManagementEnablingService(
            OrganizationManagementInitialize organizationManagementInitializeInstance) {

        OAuth2ServiceComponentHolder.getInstance().setOrganizationManagementEnable(null);
    }

    @Reference(
            name = "organization.service",
            service = OrganizationManager.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetOrganizationManager"
    )
    protected void setOrganizationManager(OrganizationManager organizationManager) {

        OAuth2ServiceComponentHolder.getInstance().setOrganizationManager(organizationManager);
        if (log.isDebugEnabled()) {
            log.debug("Set organization management service.");
        }
    }

    protected void unsetOrganizationManager(OrganizationManager organizationManager) {

        OAuth2ServiceComponentHolder.getInstance().setOrganizationManager(null);
        if (log.isDebugEnabled()) {
            log.debug("Unset organization management service.");
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

    @Reference(
            name = "org.wso2.carbon.identity.event.services.IdentityEventService",
            service = IdentityEventService.class,
            cardinality = ReferenceCardinality.OPTIONAL,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetIdentityEventService"
    )
    protected void setIdentityEventService(IdentityEventService identityEventService) {

        if (log.isDebugEnabled()) {
            log.debug("IdentityEventService set in OAuth2ServiceComponent bundle");
        }
        OAuth2ServiceComponentHolder.setIdentityEventService(identityEventService);
    }

    protected void unsetIdentityEventService(IdentityEventService identityEventService) {

        if (log.isDebugEnabled()) {
            log.debug("IdentityEventService unset in OAuth2ServiceComponent bundle");
        }
        OAuth2ServiceComponentHolder.setIdentityEventService(null);
    }

    @Reference(
            name = "consent.server.configs.mgt.service",
            service = ConsentServerConfigsManagementService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetConsentServerConfigsManagementService"
    )

    /**
     * This method is used to set the Consent Server Configs Management Service.
     *
     * @param consentServerConfigsManagementService The Consent Server Configs Management Service which needs to be set.
     */
    protected void setConsentServerConfigsManagementService(ConsentServerConfigsManagementService
                                                                        consentServerConfigsManagementService) {

        OAuth2ServiceComponentHolder.setConsentServerConfigsManagementService(consentServerConfigsManagementService);
        log.debug("Setting the Consent Server Management Configs.");
    }

    /**
     * This method is used to unset the Consent Server Configs Management Service.
     *
     * @param consentServerConfigsManagementService The Consent Server Configs Management Service which needs to unset.
     */
    protected void unsetConsentServerConfigsManagementService(ConsentServerConfigsManagementService
                                                     consentServerConfigsManagementService) {

        OAuth2ServiceComponentHolder.setConsentServerConfigsManagementService(null);
        log.debug("Unsetting the Consent Server Configs Management.");
    }

    @Reference(
            name = "configuration.context.service",
            service = ConfigurationContextService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetConfigurationContextService"
    )
    protected void setConfigurationContextService(ConfigurationContextService configurationContextService) {

        OAuth2ServiceComponentHolder.getInstance().setConfigurationContextService(configurationContextService);
        log.debug("ConfigurationContextService Instance was set.");
    }

    protected void unsetConfigurationContextService(ConfigurationContextService configurationContextService) {

        OAuth2ServiceComponentHolder.getInstance().setConfigurationContextService(null);
        log.debug("ConfigurationContextService Instance was unset.");
    }

    @Reference(
            name = "JWTAccessTokenClaimProvider",
            service = JWTAccessTokenClaimProvider.class,
            cardinality = ReferenceCardinality.MULTIPLE,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetJWTAccessTokenClaimProvider"
    )
    protected void setJWTAccessTokenClaimProvider(JWTAccessTokenClaimProvider claimProvider) {

        if (log.isDebugEnabled()) {
            log.debug("Adding JWT Access Token ClaimProvider: " + claimProvider.getClass().getName());
        }
        OAuth2ServiceComponentHolder.getInstance().addJWTAccessTokenClaimProvider(claimProvider);
    }

    protected void unsetJWTAccessTokenClaimProvider(JWTAccessTokenClaimProvider claimProvider) {

        if (log.isDebugEnabled()) {
            log.debug("Removing JWT Access Token ClaimProvider: " + claimProvider.getClass().getName());
        }
        OAuth2ServiceComponentHolder.getInstance().removeJWTAccessTokenClaimProvider(claimProvider);
    }

    @Reference(
            name = "saml.sso.service.provider.manager",
            service = SAMLSSOServiceProviderManager.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetSAMLSSOServiceProviderManager")
    protected void setSAMLSSOServiceProviderManager(SAMLSSOServiceProviderManager samlSSOServiceProviderManager) {

        OAuth2ServiceComponentHolder.getInstance().setSamlSSOServiceProviderManager(samlSSOServiceProviderManager);
        if (log.isDebugEnabled()) {
            log.debug("SAMLSSOServiceProviderManager set in to bundle");
        }
    }

    protected void unsetSAMLSSOServiceProviderManager(SAMLSSOServiceProviderManager samlSSOServiceProviderManager) {

        OAuth2ServiceComponentHolder.getInstance().setSamlSSOServiceProviderManager(null);
        if (log.isDebugEnabled()) {
            log.debug("SAMLSSOServiceProviderManager unset in to bundle");
        }
    }

    @Reference(
            name = "identity.application.authentication.framework",
            service = ApplicationAuthenticationService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetApplicationAuthenticationService"
    )
    protected void setApplicationAuthenticationService(
            ApplicationAuthenticationService applicationAuthenticationService) {
        /* reference ApplicationAuthenticationService service to guarantee that this component will wait until
        authentication framework is started */
    }

    protected void unsetApplicationAuthenticationService(
            ApplicationAuthenticationService applicationAuthenticationService) {
        /* reference ApplicationAuthenticationService service to guarantee that this component will wait until
        authentication framework is started */
    }

    /**
     * Set realm service implementation.
     *
     * @param realmService RealmService
     */
    @Reference(
            name = "user.realmservice.default",
            service = RealmService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRealmService"
    )
    protected void setRealmService(RealmService realmService) {

        OAuth2ServiceComponentHolder.getInstance().setRealmService(realmService);
    }

    /**
     * Unset realm service implementation.
     *
     * @param realmService RealmService
     */
    protected void unsetRealmService(RealmService realmService) {

        OAuth2ServiceComponentHolder.getInstance().setRealmService(null);
    }

    @Reference(
            name = "identity.authorized.api.management.component",
            service = AuthorizedAPIManagementService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetAuthorizedAPIManagementService"
    )
    protected void setAuthorizedAPIManagementService(AuthorizedAPIManagementService authorizedAPIManagementService) {

        if (log.isDebugEnabled()) {
            log.debug("Adding Authorized API Management Service: " + authorizedAPIManagementService.getClass()
                    .getName());
        }
        OAuth2ServiceComponentHolder.getInstance()
                .setAuthorizedAPIManagementService(authorizedAPIManagementService);
    }

    protected void unsetAuthorizedAPIManagementService(AuthorizedAPIManagementService authorizedAPIManagementService) {

        if (log.isDebugEnabled()) {
            log.debug("Removing Authorized API Management Service: " + authorizedAPIManagementService.getClass()
                    .getName());
        }
        OAuth2ServiceComponentHolder.getInstance().setAuthorizedAPIManagementService(null);
    }

    @Reference(
            name = "api.resource.mgt.service.component",
            service = APIResourceManager.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetAPIResourceManagerService"
    )
    protected void setAPIResourceManagerService(APIResourceManager apiResourceManager) {

        if (log.isDebugEnabled()) {
            log.debug("Adding API Resource Manager: " + apiResourceManager.getClass().getName());
        }
        OAuth2ServiceComponentHolder.getInstance().setApiResourceManager(apiResourceManager);
    }
    protected void unsetAPIResourceManagerService(APIResourceManager apiResourceManager) {

        if (log.isDebugEnabled()) {
            log.debug("Removing API Resource Manager: " + apiResourceManager.getClass().getName());
        }
        OAuth2ServiceComponentHolder.getInstance().setApiResourceManager(null);
    }

    /**
     * Set role management service V2 implementation.
     *
     * @param roleManagementService RoleManagementServiceV2.
     */
    @Reference(
            name = "org.wso2.carbon.identity.role.v2.mgt.core.RoleManagementService",
            service = org.wso2.carbon.identity.role.v2.mgt.core.RoleManagementService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRoleManagementServiceV2")
    protected void setRoleManagementServiceV2(RoleManagementService roleManagementService) {

        if (log.isDebugEnabled()) {
            log.debug("Adding Role Management  Service V2: " + roleManagementService.getClass().getName());
        }
        OAuth2ServiceComponentHolder.getInstance().setRoleManagementServiceV2(roleManagementService);
    }

    /**
     * Unset role management service V2 implementation.
     *
     * @param roleManagementService RoleManagementServiceV2
     */
    protected void unsetRoleManagementServiceV2(RoleManagementService roleManagementService) {

        if (log.isDebugEnabled()) {
            log.debug("Removing Role Management  Service V2: " + roleManagementService.getClass().getName());
        }
        OAuth2ServiceComponentHolder.getInstance().setRoleManagementServiceV2(null);
    }
}
