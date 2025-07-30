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

package org.wso2.carbon.identity.oauth2.impersonation;

import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.testng.MockitoTestNGListener;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.model.ImpersonatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.handler.event.account.lock.service.AccountDisableService;
import org.wso2.carbon.identity.handler.event.account.lock.service.AccountLockService;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeReqDTO;
import org.wso2.carbon.identity.oauth2.impersonation.models.ImpersonationContext;
import org.wso2.carbon.identity.oauth2.impersonation.models.ImpersonationRequestDTO;
import org.wso2.carbon.identity.oauth2.impersonation.validators.UserAccountStatusValidator;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;

import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.ORGANIZATION_LOGIN_IDP_NAME;
import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.ResidentIdpPropertyName.ACCOUNT_DISABLE_HANDLER_ENABLE_PROPERTY;

/**
 * Unit test class for {@link UserAccountStatusValidator}.
 */
@Listeners(MockitoTestNGListener.class)
public class UserAccountStatusValidatorTest {

    @Mock
    private AuthenticatedUser impersonator;
    @Mock
    private ImpersonatedUser impersonatedUser;
    @Mock
    private OAuth2AuthorizeReqDTO oAuth2AuthorizeReqDTO;
    @Mock
    private OAuthAuthzReqMessageContext oAuthAuthzReqMessageContext;
    private ImpersonationRequestDTO impersonationRequestDTO;
    private static final String[] SCOPES_WITHOUT_OPENID = new String[]{"scope1", "scope2"};
    @Mock
    private AccountLockService mockAccountLockService;
    @Mock
    private AccountDisableService mockAccountDisableService;
    @Mock
    private OrganizationManager organizationManager;

    @BeforeMethod
    public void setUp() throws Exception {

        lenient().when(impersonator.getLoggableMaskedUserId()).thenReturn("123456789");
        lenient().when(impersonator.getTenantDomain()).thenReturn("carbon.super");
        when(impersonator.getImpersonatedUser()).thenReturn(impersonatedUser);

        lenient().when(impersonatedUser.getUserId()).thenReturn("dummySubjectId");
        lenient().when(impersonatedUser.getUserName()).thenReturn("dummySubjectUserName");
        lenient().when(impersonatedUser.getUserStoreDomain()).thenReturn("PRIMARY");


        lenient().when(oAuth2AuthorizeReqDTO.getRequestedSubjectId()).thenReturn("dummySubjectId");
        lenient().when(oAuth2AuthorizeReqDTO.getUser()).thenReturn(impersonator);
        lenient().when(oAuth2AuthorizeReqDTO.getConsumerKey()).thenReturn("dummyConsumerKey");
        lenient().when(oAuth2AuthorizeReqDTO.getScopes()).thenReturn(SCOPES_WITHOUT_OPENID);
        lenient().when(oAuth2AuthorizeReqDTO.getTenantDomain()).thenReturn("carbon.super");
        lenient().when(oAuthAuthzReqMessageContext.getAuthorizationReqDTO()).thenReturn(oAuth2AuthorizeReqDTO);

        impersonationRequestDTO = new ImpersonationRequestDTO();
        impersonationRequestDTO.setoAuthAuthzReqMessageContext(oAuthAuthzReqMessageContext);
        impersonationRequestDTO.setSubject("dummySubjectId");
        impersonationRequestDTO.setImpersonator(impersonator);
        impersonationRequestDTO.setClientId("dummyConsumerKey");
        impersonationRequestDTO.setScopes(SCOPES_WITHOUT_OPENID);
        impersonationRequestDTO.setTenantDomain("carbon.super");
    }

    @DataProvider(name = "getImpersonationRequestData")
    public Object[][] getImpersonationRequestData() {

        return new Object[][]{
                // accountLocked, accountDisabled, isDisableFeatureEnabled, expected
                // Account is locked → always false
                {true, false, false, null, null, false},
                {true, true, false, null, null, false},
                {true, false, true, null, null, false},
                {true, true, true, null, null, false},
                // Account is not locked, feature disabled → result depends only on lock
                {false, false, false, null, null, true},  // feature off, not locked, not disabled → allow
                {false, true, false, null, null, true},   // feature off, not locked, disabled → still allow
                // Account is not locked, feature enabled, disabled → false
                {false, true, true, null, null, false},
                // Account is not locked, feature enabled, not disabled → allow
                {false, false, true, null, null, true},
                {true, false, false, "dummyOrg1", "dummyOrg1", false},
                {false, true, false, "dummyOrg1", "dummyOrg1", true},
                {false, false, false, "dummyOrg1", "dummyOrg1", true},
                {false, true, true, "dummyOrg1", "dummyOrg1", false}
        };
    }

    @Test(dataProvider = "getImpersonationRequestData")
    public void testValidateImpersonation(boolean accountLocked, boolean accountDisabled,
                                          boolean isDisableFeatureEnabled, String residentOrg, String accessingOrg,
                                          boolean expected)
            throws IdentityException, OrganizationManagementException {

        try (MockedStatic<OAuthServerConfiguration> oAuthServerConfiguration = mockStatic(
                        OAuthServerConfiguration.class);
             MockedStatic<OAuth2ServiceComponentHolder> oAuth2ServiceComponentHolder =
                     mockStatic(OAuth2ServiceComponentHolder.class, Mockito.CALLS_REAL_METHODS);
             MockedStatic<FrameworkUtils> frameworkUtils = mockStatic(FrameworkUtils.class);) {

            // Prepare OAuthServerConfiguration.
            OAuthServerConfiguration mockOAuthServerConfiguration = mock(OAuthServerConfiguration.class);
            oAuthServerConfiguration.when(OAuthServerConfiguration::getInstance)
                    .thenReturn(mockOAuthServerConfiguration);
            lenient().when(mockOAuthServerConfiguration.getTimeStampSkewInSeconds()).thenReturn(3600L);

            // Prepare services.
            OAuth2ServiceComponentHolder.setAccountLockService(mockAccountLockService);
            OAuth2ServiceComponentHolder.setAccountDisableService(mockAccountDisableService);
            OAuth2ServiceComponentHolder.getInstance().setOrganizationManager(organizationManager);

            // Prepare impersonator.
            String residentOrgHandle = residentOrg + ".com";
            if (residentOrg != null) {
                lenient().when(impersonator.getUserResidentOrganization()).thenReturn(residentOrg);
                lenient().when(impersonatedUser.getUserResidentOrganization()).thenReturn(residentOrg);
                lenient().when(organizationManager.resolveTenantDomain(residentOrg))
                        .thenReturn(residentOrgHandle);
            }
            if (accessingOrg != null) {
                lenient().when(impersonator.getAccessingOrganization()).thenReturn(accessingOrg);
                lenient().when(impersonatedUser.getAccessingOrganization()).thenReturn(accessingOrg);
            }
            if (residentOrg != null && accessingOrg != null) {
                lenient().when(impersonator.getFederatedIdPName()).thenReturn(ORGANIZATION_LOGIN_IDP_NAME);
                lenient().when(impersonator.isFederatedUser()).thenReturn(true);
                lenient().when(impersonatedUser.getFederatedIdPName()).thenReturn(ORGANIZATION_LOGIN_IDP_NAME);
                lenient().when(impersonatedUser.isFederatedUser()).thenReturn(true);
            }
            when(impersonatedUser.getTenantDomain()).thenReturn("carbon.super");

            // Mock service output.
            lenient().when(mockAccountLockService.isAccountLocked(impersonatedUser.getUserName(),
                    impersonationRequestDTO.getTenantDomain(), impersonatedUser.getUserStoreDomain()))
                    .thenReturn(accountLocked);
            lenient().when(mockAccountDisableService.isAccountDisabled(impersonatedUser.getUserName(),
                    impersonationRequestDTO.getTenantDomain(), impersonatedUser.getUserStoreDomain()))
                    .thenReturn(accountDisabled && isDisableFeatureEnabled);
            Property accountDisableConfigProperty = new Property();
            accountDisableConfigProperty.setValue(String.valueOf(isDisableFeatureEnabled));
            frameworkUtils.when(() -> FrameworkUtils.getResidentIdpConfiguration(
                    ACCOUNT_DISABLE_HANDLER_ENABLE_PROPERTY, impersonationRequestDTO.getTenantDomain()))
                    .thenReturn(accountDisableConfigProperty);

            // Invoke impersonation validation.
            if (ORGANIZATION_LOGIN_IDP_NAME.equals(impersonator.getFederatedIdPName())) {
                lenient().when(mockAccountLockService.isAccountLocked(
                                impersonatedUser.getUserName(),
                                residentOrgHandle,
                                impersonatedUser.getUserStoreDomain()))
                        .thenReturn(accountLocked);
                lenient().when(mockAccountDisableService.isAccountDisabled(
                                impersonatedUser.getUserName(),
                                residentOrgHandle,
                                impersonatedUser.getUserStoreDomain()))
                        .thenReturn(accountDisabled && isDisableFeatureEnabled);
                accountDisableConfigProperty.setValue(String.valueOf(isDisableFeatureEnabled));
                frameworkUtils.when(() -> FrameworkUtils.getResidentIdpConfiguration(
                                ACCOUNT_DISABLE_HANDLER_ENABLE_PROPERTY,
                                residentOrgHandle))
                        .thenReturn(accountDisableConfigProperty);
            }

            ImpersonationContext impersonationContext = new ImpersonationContext();
            impersonationContext.setImpersonationRequestDTO(impersonationRequestDTO);
            UserAccountStatusValidator userAccountStatusValidator = new UserAccountStatusValidator();
            impersonationContext = userAccountStatusValidator.validateImpersonation(impersonationContext);
            // Validate results.
            assertEquals(impersonationContext.isValidated(), expected, "Impersonation validation failed.");

        }
    }
}
