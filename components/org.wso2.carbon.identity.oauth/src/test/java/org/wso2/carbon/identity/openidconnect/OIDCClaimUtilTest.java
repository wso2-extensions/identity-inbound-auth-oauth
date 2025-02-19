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

package org.wso2.carbon.identity.openidconnect;

import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.handler.approles.ApplicationRolesResolver;
import org.wso2.carbon.identity.application.authentication.framework.handler.approles.exception.ApplicationRolesException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.openidconnect.internal.OpenIDConnectServiceComponentHolder;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;

/**
 * Unit tests for OIDCClaimUtil class.
 */
public class OIDCClaimUtilTest {

    @Test
    public void testGetAppAssociatedRolesOfUser() throws ApplicationRolesException {

        try (MockedStatic<OpenIDConnectServiceComponentHolder> openIDConnectServiceComponentHolder =
                     mockStatic(OpenIDConnectServiceComponentHolder.class);) {
            AuthenticatedUser authenticatedUser = mock(AuthenticatedUser.class);
            String applicationId = "testAppId";

            ApplicationRolesResolver appRolesResolver = mock(ApplicationRolesResolver.class);
            Mockito.when(appRolesResolver.getRoles(authenticatedUser, applicationId))
                    .thenReturn(new String[]{"role1", "role2"});

            OpenIDConnectServiceComponentHolder mockOpenIDConnectServiceComponentHolder =
                    mock(OpenIDConnectServiceComponentHolder.class);
            openIDConnectServiceComponentHolder.when(OpenIDConnectServiceComponentHolder::getInstance)
                    .thenReturn(mockOpenIDConnectServiceComponentHolder);
            when(mockOpenIDConnectServiceComponentHolder.getHighestPriorityApplicationRolesResolver())
                    .thenReturn(appRolesResolver);

            String[] roles = OIDCClaimUtil.getAppAssociatedRolesOfUser(authenticatedUser, applicationId);

            assertNotNull(roles);
            assertEquals(roles.length, 2);
            assertTrue(roles[0].equals("role1") && roles[1].equals("role2"));
        }
    }
}
