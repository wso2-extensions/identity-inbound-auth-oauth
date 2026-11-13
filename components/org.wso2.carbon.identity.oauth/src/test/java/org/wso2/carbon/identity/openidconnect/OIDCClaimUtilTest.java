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

import org.apache.commons.logging.Log;
import org.mockito.ArgumentCaptor;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.handler.approles.ApplicationRolesResolver;
import org.wso2.carbon.identity.application.authentication.framework.handler.approles.exception.ApplicationRolesException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.claim.metadata.mgt.model.LocalClaim;
import org.wso2.carbon.identity.claim.metadata.mgt.util.ClaimConstants;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.openidconnect.internal.OpenIDConnectServiceComponentHolder;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
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

    @Test
    public void testLogClaimRetrievalErrorDoesNotLeakUsername() {

        String username = "john.doe@example.com";
        AuthenticatedUser user = mock(AuthenticatedUser.class);
        when(user.toString()).thenReturn(username);
        UserStoreException exception = new UserStoreException(
                "30007 - UserNotFound: User " + username + " does not exist in: PRIMARY");
        Log logger = mock(Log.class);

        try (MockedStatic<LoggerUtils> loggerUtils = mockStatic(LoggerUtils.class)) {
            loggerUtils.when(() -> LoggerUtils.getMaskedContent(username)).thenReturn("j***m");
            LoggerUtils.isLogMaskingEnable = true;
            OIDCClaimUtil.logClaimRetrievalError(logger, user, exception);
        }

        ArgumentCaptor<Object> message = ArgumentCaptor.forClass(Object.class);
        verify(logger).error(message.capture());
        verify(logger, never()).error(any(), any(Throwable.class));
        assertFalse(message.getValue().toString().contains(username));
        assertTrue(message.getValue().toString().contains("UserStoreException"));
    }

    private static final String SEPARATOR = ",";

    private static LocalClaim multiValuedLocalClaim(boolean multiValued) {

        LocalClaim localClaim = new LocalClaim("http://wso2.org/claims/testClaim");
        localClaim.setClaimProperty(ClaimConstants.MULTI_VALUED_PROPERTY, String.valueOf(multiValued));
        return localClaim;
    }

    @DataProvider(name = "isMultiValuedAttributeData")
    public Object[][] isMultiValuedAttributeData() {

        return new Object[][]{
                // Address is never rendered as an array, even when the value contains the separator
                // or the local claim metadata marks it as multivalued.
                {OAuthConstants.OIDCClaims.ADDRESS, "no 1,street", multiValuedLocalClaim(true), false},
                {OAuthConstants.OIDCClaims.ADDRESS, "no 1,street", null, false},
                // Groups is always rendered as an array, even for a single value or without metadata.
                {OAuthConstants.OIDCClaims.GROUPS, "admin", null, true},
                {OAuthConstants.OIDCClaims.GROUPS, "admin", multiValuedLocalClaim(false), true},
                // When metadata is present, the local claim multiValued property decides.
                {"email", "a@b.com", multiValuedLocalClaim(true), true},
                {"email", "a@b.com,c@d.com", multiValuedLocalClaim(false), false},
                // When metadata is absent, fall back to separator-based detection.
                {"email", "a@b.com,c@d.com", null, true},
                {"email", "a@b.com", null, false},
        };
    }

    @Test(dataProvider = "isMultiValuedAttributeData")
    public void testIsMultiValuedAttribute(String claimKey, String claimValue, LocalClaim localClaim,
                                           boolean expected) {

        assertEquals(OIDCClaimUtil.isMultiValuedAttribute(claimKey, claimValue, SEPARATOR, localClaim), expected);
    }
}
