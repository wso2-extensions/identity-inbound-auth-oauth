/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.authz.handlers.util;

import org.mockito.MockedStatic;
import org.testng.Assert;
import org.testng.annotations.Test;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.dao.AuthorizationCodeDAO;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeReqDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.AuthzCodeDO;
import org.wso2.carbon.identity.oauth2.rar.AuthorizationDetailsService;
import org.wso2.carbon.identity.oauth2.token.OauthTokenIssuer;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

/**
 * Unit tests for ResponseTypeHandlerUtil.
 */
public class ResponseTypeHandlerUtilTest {

    private static final String ORG_ID = "test-org-id";
    private static final String USER_TENANT = "user-tenant.com";
    private static final String APP_TENANT = "app-tenant.com";
    private static final String TEST_CLIENT_ID = "test-client-id";
    private static final String TEST_CALLBACK_URL = "https://callback.com";
    private static final String TEST_AUTHZ_CODE = "test-authz-code";

    @Test
    public void testGenerateAuthzCodeDoesNotOverwriteTenantDomainWhenOrgTenantMatches() throws Exception {

        OAuthAuthzReqMessageContext msgCtx = buildMsgCtxWithFederatedUser(USER_TENANT, APP_TENANT, ORG_ID);

        try (MockedStatic<OAuthServerConfiguration> mockedOAuthServerConfig =
                     mockStatic(OAuthServerConfiguration.class);
             MockedStatic<OAuth2Util> mockedOAuth2Util = mockStatic(OAuth2Util.class);
             MockedStatic<PrivilegedCarbonContext> mockedPrivilegedCarbonContext =
                     mockStatic(PrivilegedCarbonContext.class);
             MockedStatic<OAuthTokenPersistenceFactory> mockedOAuthTokenPersistenceFactory =
                     mockStatic(OAuthTokenPersistenceFactory.class);
             MockedStatic<OAuth2ServiceComponentHolder> mockedOAuth2ServiceComponentHolder =
                     mockStatic(OAuth2ServiceComponentHolder.class);
             MockedStatic<LoggerUtils> mockedLoggerUtils = mockStatic(LoggerUtils.class)) {

            OAuthServerConfiguration mockServerConfig = mock(OAuthServerConfiguration.class);
            when(mockServerConfig.getAuthorizationCodeValidityPeriodInSeconds()).thenReturn(300L);
            mockedOAuthServerConfig.when(OAuthServerConfiguration::getInstance).thenReturn(mockServerConfig);

            // The org tenant domain matches the user's tenant domain → skipTenantDomainOverWriting = true.
            mockedOAuth2Util.when(
                    () -> OAuth2Util.isFederatedRoleBasedAuthzEnabled(any(OAuthAuthzReqMessageContext.class)))
                    .thenReturn(false);
            mockedOAuth2Util.when(() -> OAuth2Util.getTenantDomainByOrgId(ORG_ID)).thenReturn(USER_TENANT);

            OauthTokenIssuer mockIssuer = mock(OauthTokenIssuer.class);
            when(mockIssuer.authorizationCode(any())).thenReturn(TEST_AUTHZ_CODE);

            PrivilegedCarbonContext mockCarbonContext = mock(PrivilegedCarbonContext.class);
            mockedPrivilegedCarbonContext.when(PrivilegedCarbonContext::getThreadLocalCarbonContext)
                    .thenReturn(mockCarbonContext);
            when(mockCarbonContext.getApplicationResidentOrganizationId()).thenReturn("");

            OAuthTokenPersistenceFactory mockPersistenceFactory = mock(OAuthTokenPersistenceFactory.class);
            mockedOAuthTokenPersistenceFactory.when(OAuthTokenPersistenceFactory::getInstance)
                    .thenReturn(mockPersistenceFactory);
            AuthorizationCodeDAO mockAuthzCodeDAO = mock(AuthorizationCodeDAO.class);
            when(mockPersistenceFactory.getAuthorizationCodeDAO()).thenReturn(mockAuthzCodeDAO);
            doNothing().when(mockAuthzCodeDAO).insertAuthorizationCode(anyString(), anyString(), anyString(),
                    anyString(), any(AuthzCodeDO.class));

            OAuth2ServiceComponentHolder mockHolder = mock(OAuth2ServiceComponentHolder.class);
            mockedOAuth2ServiceComponentHolder.when(OAuth2ServiceComponentHolder::getInstance)
                    .thenReturn(mockHolder);
            AuthorizationDetailsService mockAuthzDetailsService = mock(AuthorizationDetailsService.class);
            when(mockHolder.getAuthorizationDetailsService()).thenReturn(mockAuthzDetailsService);
            doNothing().when(mockAuthzDetailsService).storeAuthorizationCodeAuthorizationDetails(any(), any());

            mockedLoggerUtils.when(LoggerUtils::isDiagnosticLogsEnabled).thenReturn(false);

            AuthzCodeDO result = ResponseTypeHandlerUtil.generateAuthorizationCode(msgCtx, false, mockIssuer);

            Assert.assertNotNull(result);
            // Tenant domain must NOT be overwritten with the app tenant domain.
            Assert.assertEquals(result.getAuthorizedUser().getTenantDomain(), USER_TENANT);
        }
    }

    @Test
    public void testGenerateAuthzCodeOverwritesTenantDomainWhenOrgTenantDoesNotMatch() throws Exception {

        OAuthAuthzReqMessageContext msgCtx = buildMsgCtxWithFederatedUser(USER_TENANT, APP_TENANT, ORG_ID);

        try (MockedStatic<OAuthServerConfiguration> mockedOAuthServerConfig =
                     mockStatic(OAuthServerConfiguration.class);
             MockedStatic<OAuth2Util> mockedOAuth2Util = mockStatic(OAuth2Util.class);
             MockedStatic<PrivilegedCarbonContext> mockedPrivilegedCarbonContext =
                     mockStatic(PrivilegedCarbonContext.class);
             MockedStatic<OAuthTokenPersistenceFactory> mockedOAuthTokenPersistenceFactory =
                     mockStatic(OAuthTokenPersistenceFactory.class);
             MockedStatic<OAuth2ServiceComponentHolder> mockedOAuth2ServiceComponentHolder =
                     mockStatic(OAuth2ServiceComponentHolder.class);
             MockedStatic<LoggerUtils> mockedLoggerUtils = mockStatic(LoggerUtils.class)) {

            OAuthServerConfiguration mockServerConfig = mock(OAuthServerConfiguration.class);
            when(mockServerConfig.getAuthorizationCodeValidityPeriodInSeconds()).thenReturn(300L);
            mockedOAuthServerConfig.when(OAuthServerConfiguration::getInstance).thenReturn(mockServerConfig);

            // The org tenant domain does NOT match the user's tenant domain → skipTenantDomainOverWriting stays false.
            mockedOAuth2Util.when(
                    () -> OAuth2Util.isFederatedRoleBasedAuthzEnabled(any(OAuthAuthzReqMessageContext.class)))
                    .thenReturn(false);
            mockedOAuth2Util.when(() -> OAuth2Util.getTenantDomainByOrgId(ORG_ID))
                    .thenReturn("different-tenant.com");

            OauthTokenIssuer mockIssuer = mock(OauthTokenIssuer.class);
            when(mockIssuer.authorizationCode(any())).thenReturn(TEST_AUTHZ_CODE);

            PrivilegedCarbonContext mockCarbonContext = mock(PrivilegedCarbonContext.class);
            mockedPrivilegedCarbonContext.when(PrivilegedCarbonContext::getThreadLocalCarbonContext)
                    .thenReturn(mockCarbonContext);
            when(mockCarbonContext.getApplicationResidentOrganizationId()).thenReturn("");

            OAuthTokenPersistenceFactory mockPersistenceFactory = mock(OAuthTokenPersistenceFactory.class);
            mockedOAuthTokenPersistenceFactory.when(OAuthTokenPersistenceFactory::getInstance)
                    .thenReturn(mockPersistenceFactory);
            AuthorizationCodeDAO mockAuthzCodeDAO = mock(AuthorizationCodeDAO.class);
            when(mockPersistenceFactory.getAuthorizationCodeDAO()).thenReturn(mockAuthzCodeDAO);
            doNothing().when(mockAuthzCodeDAO).insertAuthorizationCode(anyString(), anyString(), anyString(),
                    anyString(), any(AuthzCodeDO.class));

            OAuth2ServiceComponentHolder mockHolder = mock(OAuth2ServiceComponentHolder.class);
            mockedOAuth2ServiceComponentHolder.when(OAuth2ServiceComponentHolder::getInstance)
                    .thenReturn(mockHolder);
            AuthorizationDetailsService mockAuthzDetailsService = mock(AuthorizationDetailsService.class);
            when(mockHolder.getAuthorizationDetailsService()).thenReturn(mockAuthzDetailsService);
            doNothing().when(mockAuthzDetailsService).storeAuthorizationCodeAuthorizationDetails(any(), any());

            mockedLoggerUtils.when(LoggerUtils::isDiagnosticLogsEnabled).thenReturn(false);

            AuthzCodeDO result = ResponseTypeHandlerUtil.generateAuthorizationCode(msgCtx, false, mockIssuer);

            Assert.assertNotNull(result);
            // Tenant domain must be overwritten with the app tenant domain.
            Assert.assertEquals(result.getAuthorizedUser().getTenantDomain(), APP_TENANT);
        }
    }

    /**
     * Build a minimal OAuthAuthzReqMessageContext with a federated user that has a resident org.
     */
    private OAuthAuthzReqMessageContext buildMsgCtxWithFederatedUser(String userTenantDomain,
                                                                     String appTenantDomain,
                                                                     String userResidentOrg) {

        AuthenticatedUser user = new AuthenticatedUser();
        user.setFederatedUser(true);
        user.setTenantDomain(userTenantDomain);
        user.setUserResidentOrganization(userResidentOrg);
        user.setUserName("testUser");
        user.setFederatedIdPName("TestFederatedIDP");

        OAuth2AuthorizeReqDTO authzReqDTO = new OAuth2AuthorizeReqDTO();
        authzReqDTO.setConsumerKey(TEST_CLIENT_ID);
        authzReqDTO.setTenantDomain(appTenantDomain);
        authzReqDTO.setCallbackUrl(TEST_CALLBACK_URL);
        authzReqDTO.setUser(user);

        OAuthAuthzReqMessageContext msgCtx = new OAuthAuthzReqMessageContext(authzReqDTO);
        msgCtx.setApprovedScope(new String[]{"openid"});
        msgCtx.setValidityPeriod(OAuthConstants.UNASSIGNED_VALIDITY_PERIOD);
        return msgCtx;
    }
}
