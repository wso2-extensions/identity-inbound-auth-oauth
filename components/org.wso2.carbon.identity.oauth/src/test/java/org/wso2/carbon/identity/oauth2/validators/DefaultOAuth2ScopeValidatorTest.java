/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.oauth2.validators;

import org.mockito.MockedStatic;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithRealmService;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.dao.SharedAppResolveDAO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeReqDTO;
import org.wso2.carbon.identity.oauth2.util.AuthzUtil;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;

/**
 * Unit tests for {@link DefaultOAuth2ScopeValidator}.
 */
@WithCarbonHome
@WithRealmService(injectToSingletons = {OAuthComponentServiceHolder.class})
public class DefaultOAuth2ScopeValidatorTest {

    @Test
    public void testValidateScopeSharedUserBypassesSharedAppResolution() throws Exception {

        try (MockedStatic<AuthzUtil> authzUtil = mockStatic(AuthzUtil.class);
             MockedStatic<SharedAppResolveDAO> sharedAppResolveDAO = mockStatic(SharedAppResolveDAO.class)) {

            // Set up shared user accessing a non-resident organization.
            AuthenticatedUser sharedUser = new AuthenticatedUser();
            sharedUser.setSharedUser(true);
            sharedUser.setAccessingOrganization("accessing-org-id");
            sharedUser.setUserResidentOrganization("resident-org-id");

            OAuth2AuthorizeReqDTO authzReqDTO = new OAuth2AuthorizeReqDTO();
            authzReqDTO.setScopes(new String[]{"openid", "profile"});
            authzReqDTO.setTenantDomain("carbon.super");
            authzReqDTO.setConsumerKey("test-client-id");
            authzReqDTO.setUser(sharedUser);
            OAuthAuthzReqMessageContext authzReqMessageContext = new OAuthAuthzReqMessageContext(authzReqDTO);

            // Mock AuthzUtil to return that user is NOT accessing resident org.
            authzUtil.when(() -> AuthzUtil.isUserAccessingResidentOrganization(sharedUser)).thenReturn(false);

            DefaultOAuth2ScopeValidator validator = new DefaultOAuth2ScopeValidator();
            try {
                validator.validateScope(authzReqMessageContext);
            } catch (IdentityOAuth2Exception e) {
                // Only ignore service-layer exceptions due to incomplete mocking of downstream dependencies.
            }

            // Verify SharedAppResolveDAO is never called for shared users.
            sharedAppResolveDAO.verify(
                    () -> SharedAppResolveDAO.resolveSharedApplication(anyString(), anyString(), anyString()),
                    never());
        }
    }
}
