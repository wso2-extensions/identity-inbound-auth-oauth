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

package org.wso2.carbon.identity.oidc.session.backchannellogout;

import com.nimbusds.jwt.JWT;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.testng.MockitoTestNGListener;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.core.ServiceURL;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.oidc.session.OIDCSessionManager;
import org.wso2.carbon.identity.oidc.session.OIDCSessionState;
import org.wso2.carbon.identity.oidc.session.internal.OIDCSessionManagementComponentServiceHolder;
import org.wso2.carbon.identity.oidc.session.util.OIDCSessionManagementUtil;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.identity.organization.management.service.util.OrganizationManagementUtil;

import java.util.HashSet;
import java.util.Set;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for DefaultLogoutTokenBuilder.
 */
@Listeners(MockitoTestNGListener.class)
public class DefaultLogoutTokenBuilderTest {

    private static final String USER_NAME = "user1";
    private static final String USER_STORE_DOMAIN = "USER_STORE_DOMAIN_NAME";
    private static final String TENANT_DOMAIN = "tenantDomain";
    private static final String CONSUMER_KEY = "ca19a540f544777860e44e75f605d927";
    private static final String CONSUMER_SECRET = "87n9a540f544777860e44e75f605d435";
    private static final String APP_NAME = "myApp";
    private static final String CALLBACK = "http://localhost:8080/redirect";
    private static final String[] SCOPE_VALIDATORS = {"org.wso2.carbon.identity.oauth2.validators.JDBCScopeValidator",
            "org.wso2.carbon.identity.oauth2.validators.XACMLScopeValidator"};
    private static final int USER_ACCESS_TOKEN_EXPIRY_TIME = 3000;
    private static final int APPLICATION_ACCESS_TOKEN_EXPIRY_TIME = 2000;
    private static final int REFRESH_TOKEN_EXPIRY_TIME = 10000;
    private static final int ID_TOKEN_EXPIRY_TIME = 5000;
    private static final String BACKCHANNEL_LOGOUT = "https://localhost:8090/playground2/backChannelLogout";
    private static final String GRANT_TYPES = "password code";

    private static final String SUPER_TENANT_TOKEN_URL = "https://localhost:9443/oauth/token";
    private static final String OTHER_TENANT_TOKEN_URL = "https://localhost:9443/t/tenantDomain/oauth2/token";
    private static final String ORGANIZATION_TOKEN_URL = "https://localhost:9443/o/orgId/oauth2/token";

    private DefaultLogoutTokenBuilder logoutTokenBuilder;
    private OAuthAppDO appDO;
    @Mock
    private OAuthServerConfiguration oAuthServerConfiguration;
    @Mock
    private OIDCSessionManager oidcSessionManager;
    @Mock
    private ServiceURLBuilder mockServiceURLBuilder;
    @Mock
    private JWT jwt;
    @Mock
    private OIDCSessionManagementComponentServiceHolder oidcSessionManagementComponentServiceHolder;
    @Mock
    private OrganizationManager organizationManager;

    @BeforeMethod
    public void setup() throws IdentityOAuth2Exception {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfigurationMockedStatic
                     = mockStatic(OAuthServerConfiguration.class);
        ) {
            oAuthServerConfigurationMockedStatic.when(OAuthServerConfiguration::getInstance)
                    .thenReturn(oAuthServerConfiguration);
            when(oAuthServerConfiguration.getIdTokenSignatureAlgorithm()).thenReturn("SHA256withRSA");
            when(oAuthServerConfiguration.getOpenIDConnectBCLogoutTokenExpiration()).thenReturn("3600");
            logoutTokenBuilder = new DefaultLogoutTokenBuilder();
        }
    }

    @DataProvider(name = "tokenUriProvider")
    public Object[][] getRedirecturi() {

        return new Object[][]{
                {TENANT_DOMAIN, false, OTHER_TENANT_TOKEN_URL},
                {TENANT_DOMAIN, true, ORGANIZATION_TOKEN_URL},
                {MultitenantConstants.SUPER_TENANT_DOMAIN_NAME, false, SUPER_TENANT_TOKEN_URL},
                {MultitenantConstants.SUPER_TENANT_DOMAIN_NAME, true, ORGANIZATION_TOKEN_URL},
        };
    }


    @Test(dataProvider = "tokenUriProvider")
    public void testBuildLogoutToken(String tenantDomain, boolean isOrganization, String url)
            throws IdentityOAuth2Exception, InvalidOAuthClientException, URLBuilderException,
            OrganizationManagementException {

        OIDCSessionState oidcSessionState = new OIDCSessionState();
        Set<String> sessionParticipants = new HashSet<>();
        sessionParticipants.add("sp1");
        oidcSessionState.setSessionParticipants(sessionParticipants);

        appDO = getDefaultOAuthAppDO(tenantDomain);

        try (MockedStatic<OIDCSessionManagementUtil> oidcSessionManagementUtilMockedStatic
                     = mockStatic(OIDCSessionManagementUtil.class);
             MockedStatic<IdentityTenantUtil> identityTenantUtilMockedStatic = mockStatic(IdentityTenantUtil.class);
             MockedStatic<OrganizationManagementUtil> organizationManagementUtilMockedStatic
                     = mockStatic(OrganizationManagementUtil.class);
                MockedStatic<ServiceURLBuilder> serviceURLBuilderMockedStatic = mockStatic(ServiceURLBuilder.class);
             MockedStatic<OAuthServerConfiguration> oAuthServerConfigurationMockedStatic
                     = mockStatic(OAuthServerConfiguration.class);
             MockedStatic<OIDCSessionManagementComponentServiceHolder> oidcSessionManagementComponentServiceHolderMocked
                     = mockStatic(OIDCSessionManagementComponentServiceHolder.class);
             MockedStatic<OAuth2Util> oAuth2UtilMockedStatic = mockStatic(OAuth2Util.class);) {

            oidcSessionManagementUtilMockedStatic.when(OIDCSessionManagementUtil::getSessionManager)
                    .thenReturn(oidcSessionManager);
            when(oidcSessionManager.getOIDCSessionState(anyString(), anyString())).thenReturn(oidcSessionState);
            oAuth2UtilMockedStatic.when(() -> OAuth2Util.getAppInformationByClientId(anyString()))
                    .thenReturn(appDO);
            oAuth2UtilMockedStatic.when(() -> OAuth2Util.getTenantDomainOfOauthApp(any(OAuthAppDO.class)))
                    .thenReturn(tenantDomain);
            oAuth2UtilMockedStatic.when(() -> OAuth2Util.signJWT(any(), any(), any()))
                    .thenReturn(jwt);

            identityTenantUtilMockedStatic.when(IdentityTenantUtil::isTenantQualifiedUrlsEnabled)
                    .thenReturn(true);
            organizationManagementUtilMockedStatic.when(() -> OrganizationManagementUtil
                            .isOrganization(appDO.getUser().getTenantDomain())).thenReturn(isOrganization);
            oAuthServerConfigurationMockedStatic.when(OAuthServerConfiguration::getInstance)
                    .thenReturn(oAuthServerConfiguration);
            oidcSessionManagementComponentServiceHolderMocked.when(
                            OIDCSessionManagementComponentServiceHolder::getInstance)
                    .thenReturn(oidcSessionManagementComponentServiceHolder);

            if (isOrganization) {
                when(oidcSessionManagementComponentServiceHolder.getOrganizationManager())
                        .thenReturn(organizationManager);
                when(organizationManager.resolveOrganizationId(tenantDomain)).thenReturn(tenantDomain);
            }

            mockServiceURLBuilder(url, serviceURLBuilderMockedStatic);

            logoutTokenBuilder.buildLogoutToken("opbsCookie");

            if (isOrganization) {
                verify(mockServiceURLBuilder).setOrganization(appDO.getUser().getTenantDomain());
            } else {
                verify(mockServiceURLBuilder).setTenant(appDO.getUser().getTenantDomain());
            }
        }
    }


    private OAuthAppDO getDefaultOAuthAppDO(String tenantDomain) {

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName(USER_NAME);
        authenticatedUser.setTenantDomain(tenantDomain);
        authenticatedUser.setUserStoreDomain(USER_STORE_DOMAIN);

        OAuthAppDO appDO = new OAuthAppDO();
        appDO.setApplicationName(APP_NAME);
        appDO.setOauthConsumerKey(CONSUMER_KEY);
        appDO.setOauthConsumerSecret(CONSUMER_SECRET);
        appDO.setUser(authenticatedUser);
        appDO.setCallbackUrl(CALLBACK);
        appDO.setBackChannelLogoutUrl(BACKCHANNEL_LOGOUT);
        appDO.setGrantTypes(GRANT_TYPES);
        appDO.setScopeValidators(SCOPE_VALIDATORS);
        appDO.setOauthVersion(OAuthConstants.OAuthVersions.VERSION_1A);
        appDO.setApplicationAccessTokenExpiryTime(APPLICATION_ACCESS_TOKEN_EXPIRY_TIME);
        appDO.setUserAccessTokenExpiryTime(USER_ACCESS_TOKEN_EXPIRY_TIME);
        appDO.setRefreshTokenExpiryTime(REFRESH_TOKEN_EXPIRY_TIME);
        appDO.setIdTokenExpiryTime(ID_TOKEN_EXPIRY_TIME);
        return appDO;
    }

    private void mockServiceURLBuilder(String url, MockedStatic<ServiceURLBuilder> serviceURLBuilder)
            throws URLBuilderException {

        serviceURLBuilder.when(ServiceURLBuilder::create).thenReturn(mockServiceURLBuilder);
        lenient().when(mockServiceURLBuilder.addPath(any())).thenReturn(mockServiceURLBuilder);
        lenient().when(mockServiceURLBuilder.setTenant(any())).thenReturn(mockServiceURLBuilder);
        lenient().when(mockServiceURLBuilder.setOrganization(any())).thenReturn(mockServiceURLBuilder);

        ServiceURL serviceURL = mock(ServiceURL.class);
        lenient().when(serviceURL.getAbsolutePublicURL()).thenReturn(url);
        lenient().when(mockServiceURLBuilder.build()).thenReturn(serviceURL);
    }
}
