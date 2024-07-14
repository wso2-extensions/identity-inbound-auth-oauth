/*
 *  Copyright (c) 2024, WSO2 LLC. (http://www.wso2.com).
 *
 *  WSO2 LLC. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */

package org.wso2.carbon.identity.oauth2.impersonation;

import org.mockito.Mock;
import org.mockito.testng.MockitoTestNGListener;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeReqDTO;
import org.wso2.carbon.identity.oauth2.impersonation.models.ImpersonationContext;
import org.wso2.carbon.identity.oauth2.impersonation.models.ImpersonationRequestDTO;
import org.wso2.carbon.identity.oauth2.impersonation.validators.ImpersonatorPermissionValidator;
import org.wso2.carbon.identity.oauth2.validators.DefaultOAuth2ScopeValidator;

import java.lang.reflect.Field;
import java.util.Arrays;

import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;
import static org.wso2.carbon.identity.oauth2.impersonation.utils.Constants.IMPERSONATION_SCOPE_NAME;

/**
 * Unit test cases for {@link ImpersonatorPermissionValidatorTest}
 */
@Listeners(MockitoTestNGListener.class)
public class ImpersonatorPermissionValidatorTest {

    @Mock
    private AuthenticatedUser impersonator;
    @Mock
    private OAuth2AuthorizeReqDTO oAuth2AuthorizeReqDTO;
    @Mock
    private OAuthAuthzReqMessageContext oAuthAuthzReqMessageContext;
    @Mock
    private DefaultOAuth2ScopeValidator defaultOAuth2ScopeValidator;
    private ImpersonationRequestDTO impersonationRequestDTO;
    private static final String[] SCOPES_WITHOUT_OPENID = new String[]{"scope1", "scope2"};

    @BeforeMethod
    public void setUp() throws Exception {

        lenient().when(impersonator.getLoggableMaskedUserId()).thenReturn("123456789");
        lenient().when(oAuth2AuthorizeReqDTO.getRequestedSubjectId()).thenReturn("dummySubjectId");
        lenient().when(oAuth2AuthorizeReqDTO.getUser()).thenReturn(impersonator);
        lenient().when(oAuth2AuthorizeReqDTO.getConsumerKey()).thenReturn("dummyConsumerKey");
        lenient().when(oAuth2AuthorizeReqDTO.getScopes()).thenReturn(SCOPES_WITHOUT_OPENID);
        lenient().when(oAuth2AuthorizeReqDTO.getTenantDomain()).thenReturn("carbon.super");
        lenient().when(oAuthAuthzReqMessageContext.getAuthorizationReqDTO()).thenReturn(oAuth2AuthorizeReqDTO);
        impersonationRequestDTO = new ImpersonationRequestDTO();
        impersonationRequestDTO.setoAuthAuthzReqMessageContext(oAuthAuthzReqMessageContext);
    }

    @Test
    public void testValidateImpersonation() throws IdentityException, NoSuchFieldException, IllegalAccessException {

        when(defaultOAuth2ScopeValidator.validateScope(oAuthAuthzReqMessageContext)).thenReturn(Arrays.asList("scope1",
                "scope2", IMPERSONATION_SCOPE_NAME));

        ImpersonationContext impersonationContext = new ImpersonationContext();
        impersonationContext.setImpersonationRequestDTO(impersonationRequestDTO);
        ImpersonatorPermissionValidator impersonatorPermissionValidator = new ImpersonatorPermissionValidator();
        Field field = ImpersonatorPermissionValidator.class.getDeclaredField("scopeValidator");
        field.setAccessible(true);
        field.set(impersonatorPermissionValidator, defaultOAuth2ScopeValidator);

        impersonationContext =
                impersonatorPermissionValidator.validateImpersonation(impersonationContext);

        assertTrue(impersonationContext.isValidated(),
                "Impersonation context's validated attribute should be true");
        assertNull(impersonationContext.getValidationFailureErrorMessage(),
                "Validation error message should be null");
    }

    @Test
    public void testValidateImpersonationNegativeCase() throws IdentityException, NoSuchFieldException,
            IllegalAccessException {

        when(defaultOAuth2ScopeValidator.validateScope(oAuthAuthzReqMessageContext)).thenReturn(Arrays.asList("scope1",
                "scope2"));

        ImpersonationContext impersonationContext = new ImpersonationContext();
        impersonationContext.setImpersonationRequestDTO(impersonationRequestDTO);
        ImpersonatorPermissionValidator impersonatorPermissionValidator = new ImpersonatorPermissionValidator();
        Field field = ImpersonatorPermissionValidator.class.getDeclaredField("scopeValidator");
        field.setAccessible(true);
        field.set(impersonatorPermissionValidator, defaultOAuth2ScopeValidator);

        impersonationContext =
                impersonatorPermissionValidator.validateImpersonation(impersonationContext);

        assertFalse(impersonationContext.isValidated(),
                "Impersonation context's validated attribute should be false");
        assertNotNull(impersonationContext.getValidationFailureErrorMessage(),
                "Validation error message shouldn't be null");
    }
}
