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

package org.wso2.carbon.identity.oauth.action.execution.versioning;

import org.apache.commons.codec.binary.Base64;
import org.testng.Assert;
import org.wso2.carbon.identity.action.execution.api.model.AllowedOperation;
import org.wso2.carbon.identity.action.execution.api.model.Header;
import org.wso2.carbon.identity.action.execution.api.model.Organization;
import org.wso2.carbon.identity.action.execution.api.model.Param;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.oauth.action.model.AccessToken;
import org.wso2.carbon.identity.oauth.action.model.PreIssueAccessTokenEvent;
import org.wso2.carbon.identity.oauth.action.model.TokenRequest;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.model.HttpRequestHeader;
import org.wso2.carbon.identity.oauth2.model.RequestParameter;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;

import java.util.Collections;
import java.util.List;

import static org.testng.AssertJUnit.assertEquals;
import static org.testng.AssertJUnit.assertNotNull;

/**
 * Base test class for PreIssueAccessTokenRequestBuilder tests (V1 & V2).
 */
public abstract class PreIssueAccessTokenRequestBuilderBaseTestCase {

    private static final String CLIENT_ID_TEST = "test-client-id";
    private static final String CLIENT_SECRET_TEST = "test-client-secret";
    private static final String GRANT_TYPE_TEST = "password";
    private static final String TENANT_DOMAIN_TEST = "carbon.super";
    private static final String USERNAME_TEST = "testUser";
    private static final String PASSWORD_TEST = "test@123";
    private static final String AUDIENCE_TEST = "audience1";

    protected void assertEvent(PreIssueAccessTokenEvent actualEvent, PreIssueAccessTokenEvent expectedEvent) {

        assertEquals(expectedEvent.getTenant().getId(), actualEvent.getTenant().getId());
        assertOrganization(expectedEvent.getOrganization(), actualEvent.getOrganization());
        assertOrganization(expectedEvent.getUser().getOrganization(), actualEvent.getUser().getOrganization());
        assertAccessToken(actualEvent.getAccessToken(), expectedEvent.getAccessToken());
        assertRequest((TokenRequest) actualEvent.getRequest(), (TokenRequest) expectedEvent.getRequest());
    }

    protected void assertOrganization(Organization expectedOrg, Organization actualOrg) {

        assertNotNull(actualOrg);
        assertEquals(actualOrg.getId(), expectedOrg.getId());
        assertEquals(actualOrg.getName(), expectedOrg.getName());
    }

    /**
     * Assert that the actual access token matches the expected access token.
     *
     * @param actualAccessToken   The actual AccessToken.
     * @param expectedAccessToken The expected AccessToken.
     */
    protected static void assertAccessToken(AccessToken actualAccessToken, AccessToken expectedAccessToken) {

        Assert.assertEquals(actualAccessToken.getClaims().size(), expectedAccessToken.getClaims().size());
        for (int i = 0; i < expectedAccessToken.getClaims().size(); i++) {
            AccessToken.Claim actualClaim = actualAccessToken.getClaims().get(i);
            AccessToken.Claim expectedClaim = expectedAccessToken.getClaims().get(i);
            Assert.assertEquals(actualClaim.getName(), expectedClaim.getName());
            Assert.assertEquals(actualClaim.getValue(), expectedClaim.getValue());
        }
        Assert.assertEquals(actualAccessToken.getScopes().size(), expectedAccessToken.getScopes().size());
        for (int i = 0; i < expectedAccessToken.getScopes().size(); i++) {
            String actualScope = expectedAccessToken.getScopes().get(i);
            String expectedScope = expectedAccessToken.getScopes().get(i);
            Assert.assertEquals(actualScope, expectedScope);
        }
    }

    /**
     * Assert that the actual token request matches the expected token request.
     *
     * @param actualRequest   The actual TokenRequest.
     * @param expectedRequest The expected TokenRequest.
     */
    protected static void assertRequest(TokenRequest actualRequest, TokenRequest expectedRequest) {

        Assert.assertEquals(actualRequest.getClientId(), expectedRequest.getClientId());
        Assert.assertEquals(actualRequest.getGrantType(), expectedRequest.getGrantType());
        Assert.assertEquals(actualRequest.getScopes().size(), expectedRequest.getScopes().size());
        for (int i = 0; i < expectedRequest.getScopes().size(); i++) {
            Assert.assertEquals(actualRequest.getScopes().get(i), expectedRequest.getScopes().get(i));
        }
        Assert.assertEquals(actualRequest.getAdditionalHeaders().size(), expectedRequest.getAdditionalHeaders().size());
        for (int i = 0; i < expectedRequest.getAdditionalHeaders().size(); i++) {
            Header actualAdditionalHeader = actualRequest.getAdditionalHeaders().get(i);
            Header expectedAdditionalHeader = expectedRequest.getAdditionalHeaders().get(i);
            Assert.assertEquals(actualAdditionalHeader.getName(), expectedAdditionalHeader.getName());
            Assert.assertEquals(actualAdditionalHeader.getValue(), expectedAdditionalHeader.getValue());
        }
        Assert.assertEquals(actualRequest.getAdditionalParams().size(), expectedRequest.getAdditionalParams().size());
        for (int i = 0; i < expectedRequest.getAdditionalParams().size(); i++) {
            Param actualAdditionalParam = actualRequest.getAdditionalParams().get(i);
            Param expectedAdditionalParam = expectedRequest.getAdditionalParams().get(i);
            Assert.assertEquals(actualAdditionalParam.getName(), expectedAdditionalParam.getName());
            Assert.assertEquals(actualAdditionalParam.getValue(), expectedAdditionalParam.getValue());
        }
    }

    /**
     * Assert that the actual allowed operations match the expected allowed operations.
     *
     * @param actual   List of actual AllowedOperation.
     * @param expected List of expected AllowedOperation.
     */
    protected void assertAllowedOperations(List<AllowedOperation> actual, List<AllowedOperation> expected) {

        Assert.assertEquals(actual.size(), expected.size());
        for (int i = 0; i < expected.size(); i++) {
            AllowedOperation expectedOperation = expected.get(i);
            AllowedOperation actualOperation = actual.get(i);
            Assert.assertEquals(expectedOperation.getOp(), actualOperation.getOp());
            Assert.assertEquals(expectedOperation.getPaths().size(), actualOperation.getPaths().size());
            for (int j = 0; j < expectedOperation.getPaths().size(); j++) {
                Assert.assertEquals(expectedOperation.getPaths().get(j), actualOperation.getPaths().get(j));
            }
        }
    }

    /**
     * Mock the OAuth2 access token request DTO.
     *
     * @return OAuth2AccessTokenReqDTO containing mock token request data.
     */
    protected OAuth2AccessTokenReqDTO mockTokenRequestDTO() {

        OAuth2AccessTokenReqDTO tokenReqDTO = new OAuth2AccessTokenReqDTO();
        tokenReqDTO.setClientId(CLIENT_ID_TEST);
        tokenReqDTO.setClientSecret(CLIENT_SECRET_TEST);
        tokenReqDTO.setGrantType(GRANT_TYPE_TEST);
        tokenReqDTO.setTenantDomain(TENANT_DOMAIN_TEST);
        tokenReqDTO.setResourceOwnerUsername(USERNAME_TEST);
        tokenReqDTO.setResourceOwnerPassword(PASSWORD_TEST);
        tokenReqDTO.setScope(new String[]{"scope1", "scope2"});
        HttpRequestHeader[] requestHeaders = new HttpRequestHeader[]{
                new HttpRequestHeader("authorization",
                        getBase64EncodedString(CLIENT_ID_TEST, CLIENT_SECRET_TEST)),
                new HttpRequestHeader("accept", "application/json")
        };
        tokenReqDTO.setHttpRequestHeaders(requestHeaders);
        RequestParameter[] requestParameters = new RequestParameter[]{
                new RequestParameter("grant_type", GRANT_TYPE_TEST),
                new RequestParameter("username", USERNAME_TEST),
                new RequestParameter("password", PASSWORD_TEST),
                new RequestParameter("scope", "scope1", "scope2")
        };
        tokenReqDTO.setRequestParameters(requestParameters);
        return tokenReqDTO;
    }

    /**
     * Mock the OAuthTokenReqMessageContext for testing.
     *
     * @param tokenReqDTO       The OAuth2AccessTokenReqDTO used in the message context.
     * @param authenticatedUser The authenticated user for the request.
     * @return OAuthTokenReqMessageContext with mock data.
     */
    protected static OAuthTokenReqMessageContext mockMessageContext(OAuth2AccessTokenReqDTO tokenReqDTO,
                                                                  AuthenticatedUser authenticatedUser) {

        OAuthTokenReqMessageContext tokenMessageContext = new OAuthTokenReqMessageContext(tokenReqDTO);
        tokenMessageContext.setAuthorizedUser(authenticatedUser);
        tokenMessageContext.setScope(new String[]{"scope1", "scope2"});

        tokenMessageContext.setPreIssueAccessTokenActionsExecuted(false);
        tokenMessageContext.setAudiences(Collections.singletonList(AUDIENCE_TEST));

        tokenMessageContext.addProperty("USER_TYPE", "APPLICATION_USER");
        tokenMessageContext.setValidityPeriod(3600000L);
        return tokenMessageContext;
    }

    /**
     * Encode the client ID and client secret as a Base64 encoded string.
     *
     * @param clientId     The client ID.
     * @param clientSecret The client secret.
     * @return Base64 encoded string representing client ID and secret.
     */
    protected String getBase64EncodedString(String clientId, String clientSecret) {

        return new String(Base64.encodeBase64((clientId + ":" + clientSecret).getBytes()));
    }
}
