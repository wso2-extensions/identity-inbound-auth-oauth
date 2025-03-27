/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.oauth.action.execution;

import org.apache.commons.collections.CollectionUtils;
import org.mockito.MockedStatic;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.action.execution.api.exception.ActionExecutionResponseProcessorException;
import org.wso2.carbon.identity.action.execution.api.model.ActionExecutionResponseContext;
import org.wso2.carbon.identity.action.execution.api.model.ActionExecutionStatus;
import org.wso2.carbon.identity.action.execution.api.model.ActionInvocationResponse;
import org.wso2.carbon.identity.action.execution.api.model.ActionInvocationSuccessResponse;
import org.wso2.carbon.identity.action.execution.api.model.FlowContext;
import org.wso2.carbon.identity.action.execution.api.model.Operation;
import org.wso2.carbon.identity.action.execution.api.model.PerformableOperation;
import org.wso2.carbon.identity.action.execution.api.model.ResponseData;
import org.wso2.carbon.identity.action.execution.api.model.Success;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.oauth.action.model.AccessToken;
import org.wso2.carbon.identity.oauth.action.model.PreIssueAccessTokenEvent;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;
import static org.wso2.carbon.identity.oauth.action.execution.PreIssueAccessTokenRequestBuilder.CLAIMS_PATH_PREFIX;
import static org.wso2.carbon.identity.oauth.action.execution.PreIssueAccessTokenRequestBuilder.SCOPES_PATH_PREFIX;

public class PreIssueAccessTokenResponseProcessorTest {

    private static final String TAIL_CHARACTER = "-";
    private AccessToken.Builder requestAccessTokenBuilder;
    private MockedStatic<LoggerUtils> loggerUtils;

    static final String ORIGINAL_ISS = "https://localhost:9443/oauth2/token";
    static final String ORIGINAL_SUB = "3da43e1c-4087-46e2-ad46-08ccc76bf616";
    static final String ORIGINAL_AUD = "k58gg864hKaeLet9v7HkrFbhqsa";
    static final String ORIGINAL_EXPIRE_IN = "1742553132";
    static final String ORIGINAL_CLIENT_ID = "7k58gg864hKaeLet9v7HkrFbhqsa";
    static final String ORIGINAL_APPLICATION_USER = "APPLICATION_USER";
    static final String[] ORIGINAL_SCOPES = new String[]{"openid", "email", "profile"};

    @BeforeClass
    public void init() {

        loggerUtils = mockStatic(LoggerUtils.class);
        loggerUtils.when(LoggerUtils::isDiagnosticLogsEnabled).thenReturn(true);

        requestAccessTokenBuilder = new AccessToken.Builder()
                .tokenType("JWT")
                .addClaim(AccessToken.ClaimNames.ISS.getName(), ORIGINAL_ISS)
                .addClaim(AccessToken.ClaimNames.SUB.getName(), ORIGINAL_SUB)
                .addClaim(AccessToken.ClaimNames.AUD.getName(),
                        List.of(ORIGINAL_AUD))
                .addClaim(AccessToken.ClaimNames.EXPIRES_IN.getName(), ORIGINAL_EXPIRE_IN)
                .addClaim(AccessToken.ClaimNames.CLIENT_ID.getName(), ORIGINAL_CLIENT_ID)
                .addClaim(AccessToken.ClaimNames.AUTHORIZED_USER_TYPE.getName(), ORIGINAL_APPLICATION_USER)
                .addClaim("CustomClaimName", "CustomClaim")
                .addScope(ORIGINAL_SCOPES[0])
                .addScope(ORIGINAL_SCOPES[1])
                .addScope(ORIGINAL_SCOPES[2]);
    }

    @Test
    void testProcessSuccessResponse_AddScope_InvalidPath() throws ActionExecutionResponseProcessorException {

        List<PerformableOperation> operationsToPerform = new ArrayList<>();
        List<String> customScopes = Arrays.asList("abc", "def");
        PerformableOperation addOpScopeAsClaims =
                createPerformableOperation(Operation.ADD, CLAIMS_PATH_PREFIX + TAIL_CHARACTER,
                        new AccessToken.Claim("scope", customScopes));

        operationsToPerform.add(addOpScopeAsClaims);

        OAuthTokenReqMessageContext updatedAuthTokenReqMessageContext =
                executeProcessSuccessResponse(operationsToPerform);
        assertFalse(
                CollectionUtils.containsAny(Arrays.asList(updatedAuthTokenReqMessageContext.getScope()), customScopes));
        assertEquals(updatedAuthTokenReqMessageContext.getScope(), ORIGINAL_SCOPES);
        assertNull(updatedAuthTokenReqMessageContext.getAdditionalAccessTokenClaims().get("scope"));
    }

    private PerformableOperation createPerformableOperation(Operation op, String path, Object value) {

        PerformableOperation performableOperation = new PerformableOperation();
        performableOperation.setOp(op);
        performableOperation.setPath(path);
        performableOperation.setValue(value);
        return performableOperation;
    }

    @Test
    void testProcessSuccessResponse_AddScope_ValidPath() throws ActionExecutionResponseProcessorException {

        List<PerformableOperation> operationsToPerform = new ArrayList<>();
        PerformableOperation addOpAScope =
                createPerformableOperation(Operation.ADD, SCOPES_PATH_PREFIX + TAIL_CHARACTER,
                        "internal_user_mgt_update");
        operationsToPerform.add(addOpAScope);

        OAuthTokenReqMessageContext oAuthTokenReqMessageContext = executeProcessSuccessResponse(operationsToPerform);
        assertNull(oAuthTokenReqMessageContext.getAdditionalAccessTokenClaims().get("scope"));
        assertTrue(
                Arrays.asList(oAuthTokenReqMessageContext.getScope()).contains(String.valueOf(addOpAScope.getValue())));

    }

    @Test
    void testProcessSuccessResponse_AddAud_InvalidPath() throws ActionExecutionResponseProcessorException {

        List<PerformableOperation> operationsToPerform = new ArrayList<>();
        PerformableOperation addOpAud = createPerformableOperation(Operation.ADD,
                CLAIMS_PATH_PREFIX + AccessToken.ClaimNames.AUD.getName() + "/-", "https://example.com/resource");
        operationsToPerform.add(addOpAud);

        OAuthTokenReqMessageContext oAuthTokenReqMessageContext = executeProcessSuccessResponse(operationsToPerform);

        assertNull(oAuthTokenReqMessageContext.getAdditionalAccessTokenClaims().get("aud"));
        assertEquals(oAuthTokenReqMessageContext.getAudiences().size(), 2);
        assertTrue(oAuthTokenReqMessageContext.getAudiences().contains(ORIGINAL_AUD));
        assertTrue(oAuthTokenReqMessageContext.getAudiences().contains(String.valueOf(addOpAud.getValue())));
    }

    @Test
    void testProcessSuccessResponse_AddAud_InvalidObj() throws ActionExecutionResponseProcessorException {

        List<String> newlyAddedAUD = Arrays.asList("https://example1.com/resource", "https://example2.com/resource");

        List<PerformableOperation> operationsToPerform = new ArrayList<>();
        PerformableOperation addOpInvalidAudObj = createPerformableOperation(Operation.ADD,
                CLAIMS_PATH_PREFIX + AccessToken.ClaimNames.AUD.getName() + "/-", newlyAddedAUD);
        operationsToPerform.add(addOpInvalidAudObj);

        OAuthTokenReqMessageContext oAuthTokenReqMessageContext = executeProcessSuccessResponse(operationsToPerform);

        assertNull(oAuthTokenReqMessageContext.getAdditionalAccessTokenClaims().get("aud"));
        assertNotEquals(oAuthTokenReqMessageContext.getAudiences().size(), 3);
        assertFalse(oAuthTokenReqMessageContext.getAudiences().contains(addOpInvalidAudObj));

        assertEquals(oAuthTokenReqMessageContext.getAudiences().size(), 1);
        assertTrue(oAuthTokenReqMessageContext.getAudiences().contains(ORIGINAL_AUD));
    }

    @Test
    void testProcessSuccessResponse_AddClaim_Valid() throws ActionExecutionResponseProcessorException {

        List<PerformableOperation> operationsToPerform = new ArrayList<>();
        PerformableOperation addOpClaim = createPerformableOperation(Operation.ADD,
                CLAIMS_PATH_PREFIX + TAIL_CHARACTER, new AccessToken.Claim("isPermanent", true));
        operationsToPerform.add(addOpClaim);

        OAuthTokenReqMessageContext oAuthTokenReqMessageContext = executeProcessSuccessResponse(operationsToPerform);
        assertNotNull(oAuthTokenReqMessageContext.getAdditionalAccessTokenClaims().get("isPermanent"));
    }

    @Test
    void testProcessSuccessResponse_AddClaim_Invalid() throws ActionExecutionResponseProcessorException {

        List<PerformableOperation> operationsToPerform = new ArrayList<>();
        operationsToPerform.add(createPerformableOperation(Operation.ADD,
                CLAIMS_PATH_PREFIX, new AccessToken.Claim("isPermanent", true)));

        OAuthTokenReqMessageContext oAuthTokenReqMessageContext = executeProcessSuccessResponse(operationsToPerform);

        assertNull(oAuthTokenReqMessageContext.getAdditionalAccessTokenClaims().get("isPermanent"));
    }

    @DataProvider(name = "scopeRemovalTestData")
    public Object[][] scopeRemovalTestData() {

        return new Object[][]{
                {new String[]{SCOPES_PATH_PREFIX + TAIL_CHARACTER}, 2,
                        new String[]{ORIGINAL_SCOPES[0], ORIGINAL_SCOPES[1]}, new String[]{ORIGINAL_SCOPES[2]}},
                {new String[]{SCOPES_PATH_PREFIX + "1"}, 2, new String[]{ORIGINAL_SCOPES[0], ORIGINAL_SCOPES[2]},
                        new String[]{ORIGINAL_SCOPES[1]}},
                {new String[]{SCOPES_PATH_PREFIX + "2", SCOPES_PATH_PREFIX + "1"}, 1, new String[]{ORIGINAL_SCOPES[0]},
                        new String[]{ORIGINAL_SCOPES[1], ORIGINAL_SCOPES[2]}}
        };
    }

    @Test(dataProvider = "scopeRemovalTestData")
    void testProcessSuccessResponse_RemoveScope_Valid(String[] paths, int expectedSize, String[] expectedScopes,
                                                      String[] removedScopes)
            throws ActionExecutionResponseProcessorException {

        List<PerformableOperation> operationsToPerform = new ArrayList<>();
        for (String path : paths) {
            operationsToPerform.add(createPerformableOperation(Operation.REMOVE, path, null));
        }

        OAuthTokenReqMessageContext oAuthTokenReqMessageContext = executeProcessSuccessResponse(operationsToPerform);
        assertNull(oAuthTokenReqMessageContext.getAdditionalAccessTokenClaims().get("scope"));
        List<String> resultedScopes = Arrays.asList(oAuthTokenReqMessageContext.getScope());
        assertEquals(resultedScopes.size(), expectedSize);
        for (String scope : expectedScopes) {
            assertTrue(resultedScopes.contains(scope));
        }
        for (String scope : removedScopes) {
            assertFalse(resultedScopes.contains(scope));
        }
    }

    @Test
    void testProcessSuccessResponse_RemoveScope_Invalid() throws ActionExecutionResponseProcessorException {

        List<PerformableOperation> operationsToPerform = new ArrayList<>();
        operationsToPerform.add(createPerformableOperation(Operation.REMOVE, SCOPES_PATH_PREFIX + TAIL_CHARACTER,
                Arrays.asList(ORIGINAL_SCOPES[1], ORIGINAL_SCOPES[2])));

        OAuthTokenReqMessageContext oAuthTokenReqMessageContext = executeProcessSuccessResponse(operationsToPerform);

        assertNull(oAuthTokenReqMessageContext.getAdditionalAccessTokenClaims().get("scope"));

        List<String> resultedScopes = Arrays.asList(oAuthTokenReqMessageContext.getScope());
        assertNotEquals(resultedScopes.size(), 1);
        assertTrue(resultedScopes.contains(ORIGINAL_SCOPES[0]));
        assertTrue(resultedScopes.contains(ORIGINAL_SCOPES[1]));
        assertFalse(resultedScopes.contains(ORIGINAL_SCOPES[2]));
        assertEquals(resultedScopes.size(), 2);
    }

    /*
    Since removing standard claims other than allowed operations are handled at the framework level, that unit
    test is not included here.
     */

    @Test
    void testProcessSuccessResponse_RemoveAud_Valid() throws ActionExecutionResponseProcessorException {

        List<PerformableOperation> operationsToPerform = new ArrayList<>();
        operationsToPerform.add(createPerformableOperation(Operation.REMOVE,
                CLAIMS_PATH_PREFIX + AccessToken.ClaimNames.AUD.getName() + "/0", null));

        OAuthTokenReqMessageContext oAuthTokenReqMessageContext = executeProcessSuccessResponse(operationsToPerform);
        List<String> resultedAudiences = oAuthTokenReqMessageContext.getAudiences();
        assertNotNull(resultedAudiences);
        assertTrue(resultedAudiences.isEmpty());
    }

    @Test
    void testProcessSuccessResponse_RemoveAud_Invalid() throws ActionExecutionResponseProcessorException {

        List<PerformableOperation> operationsToPerform = new ArrayList<>();
        operationsToPerform.add(createPerformableOperation(Operation.REMOVE,
                CLAIMS_PATH_PREFIX + AccessToken.ClaimNames.AUD.getName() + "/", null));

        OAuthTokenReqMessageContext oAuthTokenReqMessageContext = executeProcessSuccessResponse(operationsToPerform);
        List<String> resultedAudiences = oAuthTokenReqMessageContext.getAudiences();
        assertFalse(CollectionUtils.isEmpty(resultedAudiences));
    }

    @Test
    void testProcessSuccessResponse_RemoveCustomClaim_Valid() throws ActionExecutionResponseProcessorException {

        List<PerformableOperation> operationsToPerform = new ArrayList<>();
        operationsToPerform.add(createPerformableOperation(Operation.REMOVE,
                CLAIMS_PATH_PREFIX + "CustomClaimName/", null));

        OAuthTokenReqMessageContext oAuthTokenReqMessageContext = executeProcessSuccessResponse(operationsToPerform);
        assertNull(oAuthTokenReqMessageContext.getAdditionalAccessTokenClaims().get("CustomClaimName"));
    }

    @DataProvider(name = "replaceAudiencesTestData")
    public Object[][] replaceAudiencesTestData() {

        return new Object[][]{
                {CLAIMS_PATH_PREFIX + AccessToken.ClaimNames.AUD.getName() + "/0", "abcdefgh12345678",
                        "abcdefgh12345678"},
                {CLAIMS_PATH_PREFIX + AccessToken.ClaimNames.AUD.getName() + "/-", "abcdefgh12345678",
                        "abcdefgh12345678"},
                {CLAIMS_PATH_PREFIX + AccessToken.ClaimNames.AUD.getName() + "/", "abcdefgh12345678", ORIGINAL_AUD}
        };
    }

    @Test(dataProvider = "replaceAudiencesTestData")
    void testProcessSuccessResponse_ReplaceAud(String path, String replaceableAudience, String expectedAudience)
            throws ActionExecutionResponseProcessorException {

        List<PerformableOperation> operationsToPerform = new ArrayList<>();
        operationsToPerform.add(createPerformableOperation(Operation.REPLACE, path, replaceableAudience));

        OAuthTokenReqMessageContext oAuthTokenReqMessageContext = executeProcessSuccessResponse(operationsToPerform);
        List<String> resultedAudiences = oAuthTokenReqMessageContext.getAudiences();
        assertNotNull(resultedAudiences);
        assertEquals(resultedAudiences.get(0), expectedAudience);
    }

    @DataProvider(name = "replaceExpireInTestData")
    public Object[][] replaceExpireInTestData() {

        return new Object[][]{
                {CLAIMS_PATH_PREFIX + AccessToken.ClaimNames.EXPIRES_IN.getName(), 1000, 1000000},
                {CLAIMS_PATH_PREFIX + AccessToken.ClaimNames.EXPIRES_IN.getName() + "/", 1000, 1000000}
        };
    }

    @Test(dataProvider = "replaceExpireInTestData")
    void testProcessSuccessResponse_ReplaceExpireIn_Valid(String path, long replaceableExpireIn, long expectedExpireIn)
            throws ActionExecutionResponseProcessorException {

        List<PerformableOperation> operationsToPerform = new ArrayList<>();
        operationsToPerform.add(createPerformableOperation(Operation.REPLACE,
                path, replaceableExpireIn));

        OAuthTokenReqMessageContext oAuthTokenReqMessageContext = executeProcessSuccessResponse(operationsToPerform);
        // Get the validity period in milliseconds
        long validityPeriod = oAuthTokenReqMessageContext.getValidityPeriod();
        assertEquals(validityPeriod, expectedExpireIn);
    }

    private OAuthTokenReqMessageContext executeProcessSuccessResponse(List<PerformableOperation> operationsToPerform)
            throws ActionExecutionResponseProcessorException {

        ActionInvocationSuccessResponse successResponse = new ActionInvocationSuccessResponse.Builder()
                .actionStatus(ActionInvocationResponse.Status.SUCCESS)
                .operations(operationsToPerform)
                .responseData(mock(ResponseData.class))
                .build();

        PreIssueAccessTokenEvent.Builder preIssueAccessTokenEventBuilder = new PreIssueAccessTokenEvent.Builder()
                .accessToken(requestAccessTokenBuilder.build());
        ActionExecutionResponseContext<ActionInvocationSuccessResponse> responseContext =
                ActionExecutionResponseContext.create(preIssueAccessTokenEventBuilder.build(), successResponse);

        PreIssueAccessTokenResponseProcessor processor = new PreIssueAccessTokenResponseProcessor();
        FlowContext flowContext = FlowContext.create();
        flowContext.add("tokenMessageContext", new OAuthTokenReqMessageContext(new OAuth2AccessTokenReqDTO()));

        ActionExecutionStatus<Success> result = processor.processSuccessResponse(flowContext, responseContext);
        assertNotNull(result);
        assertNotNull(result.getResponseContext());

        return (OAuthTokenReqMessageContext) result.getResponseContext().get("tokenMessageContext");
    }

    @AfterClass
    public void tearDown() {

        loggerUtils.close();
    }
}
