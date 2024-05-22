/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth2.impersonation;

import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeReqDTO;
import org.wso2.carbon.identity.oauth2.impersonation.models.ImpersonationContext;
import org.wso2.carbon.identity.oauth2.impersonation.models.ImpersonationRequestDTO;
import org.wso2.carbon.identity.oauth2.impersonation.validators.SubjectScopeValidator;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.oauth2.validators.DefaultOAuth2ScopeValidator;
import org.wso2.carbon.identity.testutil.powermock.PowerMockIdentityBaseTest;

import java.lang.reflect.Field;
import java.util.Arrays;

import static org.mockito.Mockito.when;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;
import static org.wso2.carbon.identity.oauth2.impersonation.utils.Constants.OAUTH_2;

/**
 * Unit test cases for {@link SubjectScopeValidatorTest}
 */
@PrepareForTest(
        {
                OAuth2ServiceComponentHolder.class,
                OAuth2Util.class,
                OAuthServerConfiguration.class
        }
)
public class SubjectScopeValidatorTest extends PowerMockIdentityBaseTest {

    @Mock
    private AuthenticatedUser impersonator;
    @Mock
    private OAuth2AuthorizeReqDTO oAuth2AuthorizeReqDTO;
    @Mock
    private OAuthAuthzReqMessageContext oAuthAuthzReqMessageContext;
    @Mock
    private DefaultOAuth2ScopeValidator defaultOAuth2ScopeValidator;
    @Mock
    private ApplicationManagementService applicationManagementService;
    @Mock
    private AuthenticatedUser endUser;
    @Mock
    private OAuthServerConfiguration oAuthServerConfiguration;

    private ImpersonationRequestDTO impersonationRequestDTO;
    private static final String[] SCOPES_WITHOUT_OPENID = new String[]{"scope1", "scope2"};

    @BeforeMethod
    public void setUp() throws Exception {

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(oAuthServerConfiguration);
        mockStatic(OAuth2Util.class);
        mockStatic(OAuth2ServiceComponentHolder.class);
        mockStatic(OAuth2Util.class);
        when(OAuth2ServiceComponentHolder.getApplicationMgtService()).thenReturn(applicationManagementService);
        when(applicationManagementService.getApplicationResourceIDByInboundKey("dummyConsumerKey",
                OAUTH_2, "carbon.super")).thenReturn("dummyAppId");
        when(impersonator.getLoggableMaskedUserId()).thenReturn("123456789");
        when(oAuth2AuthorizeReqDTO.getRequestedSubjectId()).thenReturn("dummySubjectId");
        when(oAuth2AuthorizeReqDTO.getUser()).thenReturn(impersonator);
        when(oAuth2AuthorizeReqDTO.getConsumerKey()).thenReturn("dummyConsumerKey");
        when(oAuth2AuthorizeReqDTO.getScopes()).thenReturn(SCOPES_WITHOUT_OPENID);
        when(oAuth2AuthorizeReqDTO.getTenantDomain()).thenReturn("carbon.super");
        when(oAuthAuthzReqMessageContext.getAuthorizationReqDTO()).thenReturn(oAuth2AuthorizeReqDTO);
        when(oAuthAuthzReqMessageContext.getRequestedScopes()).thenReturn(SCOPES_WITHOUT_OPENID);
        impersonationRequestDTO = new ImpersonationRequestDTO();
        impersonationRequestDTO.setoAuthAuthzReqMessageContext(oAuthAuthzReqMessageContext);

        when(OAuth2Util.resolveUsernameFromUserId("carbon.super", "dummySubjectId"))
                .thenReturn("dummyUserName");
        when(OAuth2Util.getUserFromUserName("dummyUserName")).thenReturn(endUser);
    }

    @Test
    public void testValidateImpersonation() throws IdentityException, NoSuchFieldException, IllegalAccessException {


        when(defaultOAuth2ScopeValidator.validateScope(oAuthAuthzReqMessageContext)).thenReturn(
                Arrays.asList("scope1", "scope2"));

        ImpersonationContext impersonationContext = new ImpersonationContext();
        impersonationContext.setImpersonationRequestDTO(impersonationRequestDTO);
        SubjectScopeValidator subjectScopeValidator = new SubjectScopeValidator();
        Field field = SubjectScopeValidator.class.getDeclaredField("scopeValidator");
        field.setAccessible(true);
        field.set(subjectScopeValidator, defaultOAuth2ScopeValidator);

        impersonationContext =
                subjectScopeValidator.validateImpersonation(impersonationContext);

        assertTrue(impersonationContext.isValidated(), "Impersonation context's validated attribute should be true");
        assertNull(impersonationContext.getValidationFailureErrorMessage(),
                "Validation error message should be null");
    }

    @Test
    public void testValidateImpersonationNegativeCase() throws IdentityException, NoSuchFieldException,
            IllegalAccessException {

        when(defaultOAuth2ScopeValidator.validateScope(oAuthAuthzReqMessageContext)).thenThrow
                (IdentityOAuth2Exception.class);

        ImpersonationContext impersonationContext = new ImpersonationContext();
        impersonationContext.setImpersonationRequestDTO(impersonationRequestDTO);
        SubjectScopeValidator subjectScopeValidator = new SubjectScopeValidator();
        Field field = SubjectScopeValidator.class.getDeclaredField("scopeValidator");
        field.setAccessible(true);
        field.set(subjectScopeValidator, defaultOAuth2ScopeValidator);

        try {
            impersonationContext =
                    subjectScopeValidator.validateImpersonation(impersonationContext);
        } catch (IdentityOAuth2Exception e) {

            assertFalse(impersonationContext.isValidated(), "Impersonation context's validated" +
                    "attribute should be false");
        }
    }
}
