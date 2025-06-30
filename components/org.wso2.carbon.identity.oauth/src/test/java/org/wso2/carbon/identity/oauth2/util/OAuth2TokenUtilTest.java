/*
 *  Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
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
 */
package org.wso2.carbon.identity.oauth2.util;

import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.testng.MockitoTestNGListener;
import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.services.IdentityEventService;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.model.TokenIssuanceDO;
import org.wso2.carbon.identity.openidconnect.OIDCConstants;
import org.wso2.carbon.identity.openidconnect.internal.OpenIDConnectServiceComponentHolder;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mockStatic;

/**
 * Unit tests for OAuth2TokenUtil class.
 */
@Listeners(MockitoTestNGListener.class)
@WithCarbonHome
public class OAuth2TokenUtilTest {

    @Mock
    private IdentityEventService identityEventService;;

    @DataProvider
    public static Object[][] postTokenDataProvider() {

        return new Object[][] {
                { new TokenIssuanceDO.Builder()
                    .tokenId("12345")
                    .tokenType("Bearer")
                    .tenantDomain("carbon.super")
                    .clientId("client123")
                    .grantType("client_credentials")
                    .tokenBillingCategory(OIDCConstants.TokenBillingCategory.M2M_ACCESS_TOKEN)
                    .appResidentTenantId(1)
                    .issuedTime("2023-10-01T12:00:00Z")
                    .authorizedOrganizationId("org123").build()
                }
        };
    }

    @Test(dataProvider = "postTokenDataProvider")
    public void testPostIssueToken(TokenIssuanceDO tokenIssuanceDO) throws Exception {

        try (
                MockedStatic<OpenIDConnectServiceComponentHolder> openIDConnectServiceComponentHolder
                        = mockStatic(OpenIDConnectServiceComponentHolder.class);
        ) {
            openIDConnectServiceComponentHolder.when(OpenIDConnectServiceComponentHolder::getIdentityEventService)
                    .thenReturn(identityEventService);
            OAuth2TokenUtil.postIssueToken(tokenIssuanceDO);
        }
    }

    @Test(dataProvider = "postTokenDataProvider")
    public void testPostIssueTokenWithException(TokenIssuanceDO tokenIssuanceDO) throws Exception {

        try (
                MockedStatic<OpenIDConnectServiceComponentHolder> openIDConnectServiceComponentHolder
                        = mockStatic(OpenIDConnectServiceComponentHolder.class);
        ) {
            openIDConnectServiceComponentHolder.when(OpenIDConnectServiceComponentHolder::getIdentityEventService)
                    .thenReturn(identityEventService);
            doThrow(new IdentityEventException("Error posting token issuance event"))
                    .when(identityEventService).handleEvent(any(Event.class));
            OAuth2TokenUtil.postIssueToken(tokenIssuanceDO);
        } catch (IdentityOAuth2Exception e) {
            // Expected exception, test should pass.
            Assert.assertEquals(e.getMessage(), "Error while invoking the request object " +
                    "persistence handler when issuing the access token id: " + tokenIssuanceDO.getTokenId());
        }
    }
}
