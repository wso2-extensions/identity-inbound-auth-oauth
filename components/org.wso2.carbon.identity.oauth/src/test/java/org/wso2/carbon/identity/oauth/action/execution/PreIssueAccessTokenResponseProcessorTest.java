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

    String original_iss = "https://localhost:9443/oauth2/token";
    String original_sub = "3da43e1c-4087-46e2-ad46-08ccc76bf616";
    String original_aud = "k58gg864hKaeLet9v7HkrFbhqsa";
    String original_expire_in = "1742553132";
    String original_clientId = "7k58gg864hKaeLet9v7HkrFbhqsa";
    String original_applicationUser = "APPLICATION_USER";

    @BeforeClass
    public void init() {

        loggerUtils = mockStatic(LoggerUtils.class);
        loggerUtils.when(LoggerUtils::isDiagnosticLogsEnabled).thenReturn(true);

        requestAccessTokenBuilder = new AccessToken.Builder()
                .tokenType("JWT")
                .addClaim(AccessToken.ClaimNames.ISS.getName(), original_iss)
                .addClaim(AccessToken.ClaimNames.SUB.getName(), original_sub)
                .addClaim(AccessToken.ClaimNames.AUD.getName(),
                        List.of(original_aud))
                .addClaim(AccessToken.ClaimNames.EXPIRES_IN.getName(), original_expire_in)
                .addClaim(AccessToken.ClaimNames.CLIENT_ID.getName(), original_clientId)
                .addClaim(AccessToken.ClaimNames.AUTHORIZED_USER_TYPE.getName(), original_applicationUser)
                .addScope("openid")
                .addScope("email")
                .addScope("profile");
    }

    @Test
    void testProcessSuccessResponse_WithInvalidScopePath() throws ActionExecutionResponseProcessorException {

        List<PerformableOperation> operationsToPerform = new ArrayList<>();
        List<String> customScopes = Arrays.asList("abc", "def");

        PerformableOperation addOpScopeAsClaims = new PerformableOperation();
        addOpScopeAsClaims.setOp(Operation.ADD);
        addOpScopeAsClaims.setPath(CLAIMS_PATH_PREFIX + TAIL_CHARACTER);
        addOpScopeAsClaims.setValue(new AccessToken.Claim("scope", customScopes));
        operationsToPerform.add(addOpScopeAsClaims);

        OAuthTokenReqMessageContext updatedAuthTokenReqMessageContext =
                executeProcessSuccessResponse(operationsToPerform);
        assertFalse(
                CollectionUtils.containsAny(Arrays.asList(updatedAuthTokenReqMessageContext.getScope()), customScopes));
        assertEquals(updatedAuthTokenReqMessageContext.getScope(), new String[]{"openid", "email", "profile"});
        assertNull(updatedAuthTokenReqMessageContext.getAdditionalAccessTokenClaims().get("scope"));
    }

    @Test
    void testProcessSuccessResponse_WithValidScopePath() throws ActionExecutionResponseProcessorException {

        List<PerformableOperation> operationsToPerform = new ArrayList<>();
        PerformableOperation addOpAScope = new PerformableOperation();
        addOpAScope.setOp(Operation.ADD);
        addOpAScope.setPath(SCOPES_PATH_PREFIX + TAIL_CHARACTER);
        addOpAScope.setValue("internal_user_mgt_update");
        operationsToPerform.add(addOpAScope);

        OAuthTokenReqMessageContext oAuthTokenReqMessageContext = executeProcessSuccessResponse(operationsToPerform);

        assertNull(oAuthTokenReqMessageContext.getAdditionalAccessTokenClaims().get("scope"));
        assertTrue(
                Arrays.asList(oAuthTokenReqMessageContext.getScope()).contains(String.valueOf(addOpAScope.getValue())));

    }

    @Test
    void testProcessSuccessResponse_WithValidAudPath() throws ActionExecutionResponseProcessorException {

        List<PerformableOperation> operationsToPerform = new ArrayList<>();
        PerformableOperation addOpAud = new PerformableOperation();
        addOpAud.setOp(Operation.ADD);
        addOpAud.setPath(CLAIMS_PATH_PREFIX + AccessToken.ClaimNames.AUD.getName() + "/-");
        addOpAud.setValue("https://example.com/resource");
        operationsToPerform.add(addOpAud);

        OAuthTokenReqMessageContext oAuthTokenReqMessageContext = executeProcessSuccessResponse(operationsToPerform);

        assertNull(oAuthTokenReqMessageContext.getAdditionalAccessTokenClaims().get("aud"));
        assertEquals(oAuthTokenReqMessageContext.getAudiences().size(), 2);
        assertTrue(oAuthTokenReqMessageContext.getAudiences().contains(String.valueOf(original_aud)));
        assertTrue(oAuthTokenReqMessageContext.getAudiences().contains(String.valueOf(addOpAud.getValue())));
    }

    @Test
    void testProcessSuccessResponse_WithInvalidAudObj() throws ActionExecutionResponseProcessorException {

        List<String> new_aud = Arrays.asList("https://example1.com/resource", "https://example2.com/resource");

        List<PerformableOperation> operationsToPerform = new ArrayList<>();
        PerformableOperation addOpInvalidAudObj = new PerformableOperation();
        addOpInvalidAudObj.setOp(Operation.ADD);
        addOpInvalidAudObj.setPath(CLAIMS_PATH_PREFIX + AccessToken.ClaimNames.AUD.getName() + "/-");
        addOpInvalidAudObj.setValue(new_aud);
        operationsToPerform.add(addOpInvalidAudObj);

        OAuthTokenReqMessageContext oAuthTokenReqMessageContext = executeProcessSuccessResponse(operationsToPerform);

        assertNull(oAuthTokenReqMessageContext.getAdditionalAccessTokenClaims().get("aud"));
        assertNotEquals(oAuthTokenReqMessageContext.getAudiences().size(), 3);
        assertFalse(oAuthTokenReqMessageContext.getAudiences().contains(addOpInvalidAudObj));

        assertEquals(oAuthTokenReqMessageContext.getAudiences().size(), 1);
        assertTrue(oAuthTokenReqMessageContext.getAudiences().contains(original_aud));
    }

    @Test
    void testProcessSuccessResponse_WithValidClaim() throws ActionExecutionResponseProcessorException {

        List<PerformableOperation> operationsToPerform = new ArrayList<>();
        PerformableOperation addOpClaim = new PerformableOperation();
        addOpClaim.setOp(Operation.ADD);
        addOpClaim.setPath(CLAIMS_PATH_PREFIX + TAIL_CHARACTER);
        addOpClaim.setValue(new AccessToken.Claim("isPermanent", true));
        operationsToPerform.add(addOpClaim);

        OAuthTokenReqMessageContext oAuthTokenReqMessageContext = executeProcessSuccessResponse(operationsToPerform);

        assertNotNull(oAuthTokenReqMessageContext.getAdditionalAccessTokenClaims().get("isPermanent"));
    }

    @Test
    void testProcessSuccessResponse_WithInvalidClaim() throws ActionExecutionResponseProcessorException {

        List<PerformableOperation> operationsToPerform = new ArrayList<>();
        PerformableOperation addOpClaim = new PerformableOperation();
        addOpClaim.setOp(Operation.ADD);
        addOpClaim.setPath(CLAIMS_PATH_PREFIX);
        addOpClaim.setValue(new AccessToken.Claim("isPermanent", true));
        operationsToPerform.add(addOpClaim);

        OAuthTokenReqMessageContext oAuthTokenReqMessageContext = executeProcessSuccessResponse(operationsToPerform);

        assertNull(oAuthTokenReqMessageContext.getAdditionalAccessTokenClaims().get("isPermanent"));
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