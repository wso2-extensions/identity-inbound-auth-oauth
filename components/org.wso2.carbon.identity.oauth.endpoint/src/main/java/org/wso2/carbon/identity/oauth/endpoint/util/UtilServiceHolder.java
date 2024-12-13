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

package org.wso2.carbon.identity.oauth.endpoint.util;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.handler.request.impl.consent.SSOConsentService;
import org.wso2.carbon.identity.discovery.DefaultOIDCProcessor;
import org.wso2.carbon.identity.discovery.OIDCProcessor;
import org.wso2.carbon.identity.discovery.builders.DefaultOIDCProviderRequestBuilder;
import org.wso2.carbon.identity.discovery.builders.OIDCProviderRequestBuilder;
import org.wso2.carbon.identity.oauth.OAuthAdminServiceImpl;
import org.wso2.carbon.identity.oauth.ciba.api.CibaAuthService;
import org.wso2.carbon.identity.oauth.ciba.api.CibaAuthServiceImpl;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.par.core.ParAuthService;
import org.wso2.carbon.identity.oauth2.OAuth2ScopeService;
import org.wso2.carbon.identity.oauth2.OAuth2Service;
import org.wso2.carbon.identity.oauth2.OAuth2TokenValidationService;
import org.wso2.carbon.identity.oauth2.scopeservice.APIResourceBasedScopeMetadataService;
import org.wso2.carbon.identity.oauth2.scopeservice.ScopeMetadataService;
import org.wso2.carbon.identity.openidconnect.RequestObjectService;
import org.wso2.carbon.identity.webfinger.DefaultWebFingerProcessor;
import org.wso2.carbon.identity.webfinger.WebFingerProcessor;
import org.wso2.carbon.idp.mgt.IdpManager;

import java.util.List;

/**
 * Service holder for managing instances of OAuth2 related services.
 */
public class UtilServiceHolder {

    private static final Log LOG = LogFactory.getLog(UtilServiceHolder.class);

    private static class IdpManagerServiceHolder {

        private static final IdpManager SERVICE = (IdpManager) PrivilegedCarbonContext.getThreadLocalCarbonContext()
                .getOSGiService(IdpManager.class, null);
    }

    private static class OAuth2ServiceHolder {

        private static final OAuth2Service SERVICE = (OAuth2Service) PrivilegedCarbonContext
                .getThreadLocalCarbonContext().getOSGiService(OAuth2Service.class, null);
    }

    private static class OAuth2ScopeServiceHolder {

            private static final OAuth2ScopeService SERVICE = (OAuth2ScopeService) PrivilegedCarbonContext
                    .getThreadLocalCarbonContext().getOSGiService(OAuth2ScopeService.class, null);
    }

    private static class OAuthAdminServiceImplHolder {

        private static final OAuthAdminServiceImpl SERVICE = (OAuthAdminServiceImpl) PrivilegedCarbonContext
                .getThreadLocalCarbonContext().getOSGiService(OAuthAdminServiceImpl.class, null);
    }

    private static class SSOConsentServiceHolder {

        private static final SSOConsentService SERVICE = (SSOConsentService) PrivilegedCarbonContext
                .getThreadLocalCarbonContext().getOSGiService(SSOConsentService.class, null);
    }

    private static class OAuthServerConfigurationHolder {

            private static final OAuthServerConfiguration SERVICE = (OAuthServerConfiguration) PrivilegedCarbonContext
                    .getThreadLocalCarbonContext().getOSGiService(OAuthServerConfiguration.class, null);
    }

    private static class RequestObjectServiceHolder {

        private static final RequestObjectService SERVICE = (RequestObjectService) PrivilegedCarbonContext
                .getThreadLocalCarbonContext().getOSGiService(RequestObjectService.class, null);
    }

    private static class ScopeMetadataServiceHolder {

        private static final ScopeMetadataService SERVICE = setScopeMetadataService();
    }

    private static ScopeMetadataService setScopeMetadataService() {

        ScopeMetadataService scopeMetadataService = getScopeMetadataServiceFromConfig();
        if (scopeMetadataService != null) {
            return scopeMetadataService;
        }

        // Get the OSGi services registered for ScopeService interface.
        List<Object> scopeServices = PrivilegedCarbonContext
                .getThreadLocalCarbonContext().getOSGiServices(ScopeMetadataService.class, null);
        if (scopeServices != null && !scopeServices.isEmpty()) {
            if (CarbonConstants.ENABLE_LEGACY_AUTHZ_RUNTIME) {
                for (Object scopeService : scopeServices) {
                    if (scopeService instanceof OAuth2ScopeService) {
                        scopeMetadataService = (ScopeMetadataService) scopeService;
                    }
                }
            } else {
                for (Object scopeService : scopeServices) {
                    if (scopeService instanceof APIResourceBasedScopeMetadataService) {
                        scopeMetadataService = (APIResourceBasedScopeMetadataService) scopeService;
                    }
                }
            }
        }

        if (scopeMetadataService == null) {
            throw new IllegalStateException("ScopeMetadataService is not available from OSGi context.");
        }
        return scopeMetadataService;
    }

    private static class WebfingerServiceHolder {

        private static final WebFingerProcessor SERVICE = (DefaultWebFingerProcessor) PrivilegedCarbonContext
                .getThreadLocalCarbonContext().getOSGiService(WebFingerProcessor.class, null);
    }

    private static class OIDProviderRequestValidatorHolder {

        private static final DefaultOIDCProviderRequestBuilder SERVICE = (DefaultOIDCProviderRequestBuilder)
                PrivilegedCarbonContext.getThreadLocalCarbonContext().getOSGiService
                        (OIDCProviderRequestBuilder.class, null);
    }

    private static class OIDCProviderServiceHolder {

        private static final DefaultOIDCProcessor SERVICE = (DefaultOIDCProcessor) PrivilegedCarbonContext
                .getThreadLocalCarbonContext().getOSGiService(OIDCProcessor.class, null);
    }

    private static class OAuth2TokenValidatorServiceHolder {

        private static final OAuth2TokenValidationService SERVICE = (OAuth2TokenValidationService)
                PrivilegedCarbonContext.getThreadLocalCarbonContext()
                        .getOSGiService(OAuth2TokenValidationService.class, null);
    }

    private static class CibaAuthServiceImplServiceHolder {

            private static final CibaAuthServiceImpl SERVICE = (CibaAuthServiceImpl) PrivilegedCarbonContext
                    .getThreadLocalCarbonContext().getOSGiService(CibaAuthService.class, null);
    }

    private static class ParAuthServiceHolder {

        private static final ParAuthService SERVICE = (ParAuthService) PrivilegedCarbonContext
                .getThreadLocalCarbonContext().getOSGiService(ParAuthService.class, null);
    }

    public static IdpManager getIdpManager() {

        if (IdpManagerServiceHolder.SERVICE == null) {
            throw new IllegalStateException("IdpManager is not available from OSGi context.");
        }
        return IdpManagerServiceHolder.SERVICE;
    }

    public static OAuth2Service getOAuth2Service() {

        if (OAuth2ServiceHolder.SERVICE == null) {
            throw new IllegalStateException("OAuth2Service is not available from OSGi context.");
        }
        return OAuth2ServiceHolder.SERVICE;
    }

    public static OAuth2ScopeService getOAuth2ScopeService() {

        if (OAuth2ScopeServiceHolder.SERVICE == null) {
            throw new IllegalStateException("OAuth2ScopeService is not available from OSGi context.");
        }
        return OAuth2ScopeServiceHolder.SERVICE;
    }

    public static OAuthAdminServiceImpl getOAuthAdminService() {

        if (OAuthAdminServiceImplHolder.SERVICE == null) {
            throw new IllegalStateException("OAuthAdminService is not available from OSGi context.");
        }
        return OAuthAdminServiceImplHolder.SERVICE;
    }

    public static SSOConsentService getSSOConsentService() {

        if (SSOConsentServiceHolder.SERVICE == null) {
            throw new IllegalStateException("SSOConsentService is not available from OSGi context.");
        }
        return SSOConsentServiceHolder.SERVICE;
    }

    public static OAuthServerConfiguration getOAuthServerConfiguration() {

        if (OAuthServerConfigurationHolder.SERVICE == null) {
            throw new IllegalStateException("OAuthServerConfiguration is not available from OSGi context.");
        }
        return OAuthServerConfigurationHolder.SERVICE;
    }

    public static RequestObjectService getRequestObjectService() {

        if (RequestObjectServiceHolder.SERVICE == null) {
            throw new IllegalStateException("RequestObjectService is not available from OSGi context.");
        }
        return RequestObjectServiceHolder.SERVICE;
    }

    public static ScopeMetadataService getScopeMetadataService() {

        if (ScopeMetadataServiceHolder.SERVICE == null) {
            throw new IllegalStateException("ScopeMetadataService is not available from OSGi context.");
        }
        return ScopeMetadataServiceHolder.SERVICE;
    }

    public static WebFingerProcessor getWebFingerService() {

        if (WebfingerServiceHolder.SERVICE == null) {
            throw new IllegalStateException("WebFingerProcessor is not available from OSGi context.");
        }
        return WebfingerServiceHolder.SERVICE;
    }

    public static OIDCProviderRequestBuilder getOIDProviderRequestValidator() {

        if (OIDProviderRequestValidatorHolder.SERVICE == null) {
            throw new IllegalStateException("OIDCProviderRequestBuilder is not available from OSGi context.");
        }
        return OIDProviderRequestValidatorHolder.SERVICE;
    }

    public static OIDCProcessor getOIDCService() {

        if (OIDCProviderServiceHolder.SERVICE == null) {
            throw new IllegalStateException("OIDCProcessor is not available from OSGi context.");
        }
        return OIDCProviderServiceHolder.SERVICE;
    }

    public static OAuth2TokenValidationService getOAuth2TokenValidationService() {

        if (OAuth2TokenValidatorServiceHolder.SERVICE == null) {
            throw new IllegalStateException("OAuth2TokenValidationService is not available from OSGi context.");
        }
        return OAuth2TokenValidatorServiceHolder.SERVICE;
    }

    public static ParAuthService getParAuthService() {

        if (ParAuthServiceHolder.SERVICE == null) {
            throw new IllegalStateException("ParAuthService is not available from OSGi context.");
        }
        return ParAuthServiceHolder.SERVICE;
    }

    public static CibaAuthServiceImpl getCibaAuthService() {

        if (CibaAuthServiceImplServiceHolder.SERVICE == null) {
            throw new IllegalStateException("CibaAuthServiceImpl is not available from OSGi context.");
        }
        return CibaAuthServiceImplServiceHolder.SERVICE;
    }

    private static ScopeMetadataService getScopeMetadataServiceFromConfig() {

        String scopeMetadataServiceClassName = OAuthServerConfiguration.getInstance()
                .getScopeMetadataExtensionImpl();
        if (scopeMetadataServiceClassName != null) {
            try {
                String className = StringUtils.trimToEmpty(scopeMetadataServiceClassName);
                Class<?> clazz = Class.forName(className);
                Object obj = clazz.newInstance();
                if (obj instanceof ScopeMetadataService) {
                    return (ScopeMetadataService) obj;
                } else {
                    LOG.error(scopeMetadataServiceClassName + " is not an instance of " +
                            ScopeMetadataService.class.getName());
                }
            } catch (ClassNotFoundException e) {
                LOG.error("ClassNotFoundException while trying to find class " + scopeMetadataServiceClassName);
            } catch (InstantiationException e) {
                LOG.error("InstantiationException while trying to instantiate class " +
                        scopeMetadataServiceClassName);
            } catch (IllegalAccessException e) {
                LOG.error("IllegalAccessException while trying to instantiate class " +
                        scopeMetadataServiceClassName);
            }
        }
        return null;
    }
}
