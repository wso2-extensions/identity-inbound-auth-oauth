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

package org.wso2.carbon.identity.openidconnect.action.preissueidtoken.execution;

import com.nimbusds.jwt.JWTClaimsSet;
import org.apache.commons.collections.CollectionUtils;
import org.mockito.MockedStatic;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.action.execution.api.exception.ActionExecutionResponseProcessorException;
import org.wso2.carbon.identity.action.execution.api.model.ActionExecutionResponseContext;
import org.wso2.carbon.identity.action.execution.api.model.ActionExecutionStatus;
import org.wso2.carbon.identity.action.execution.api.model.ActionInvocationErrorResponse;
import org.wso2.carbon.identity.action.execution.api.model.ActionInvocationFailureResponse;
import org.wso2.carbon.identity.action.execution.api.model.ActionInvocationResponse;
import org.wso2.carbon.identity.action.execution.api.model.ActionInvocationSuccessResponse;
import org.wso2.carbon.identity.action.execution.api.model.Failure;
import org.wso2.carbon.identity.action.execution.api.model.FlowContext;
import org.wso2.carbon.identity.action.execution.api.model.Operation;
import org.wso2.carbon.identity.action.execution.api.model.PerformableOperation;
import org.wso2.carbon.identity.action.execution.api.model.ResponseData;
import org.wso2.carbon.identity.action.execution.api.model.Success;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeReqDTO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.openidconnect.action.preissueidtoken.dto.IDTokenDTO;
import org.wso2.carbon.identity.openidconnect.action.preissueidtoken.model.IDToken;
import org.wso2.carbon.identity.openidconnect.action.preissueidtoken.model.PreIssueIDTokenEvent;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;

public class PreIssueIDTokenResponseProcessorTest {

    private static final String CLAIMS_PATH_PREFIX = "/idToken/claims/";
    private static final String TAIL_CHARACTER = "-";
    private IDToken.Builder requestIDTokenBuilder;
    private MockedStatic<LoggerUtils> loggerUtils;

    static final String ORIGINAL_ISS = "https://localhost:9443/oauth2/token";
    static final String ORIGINAL_SUB = "3da43e1c-4087-46e2-ad46-08ccc76bf616";
    static final String ORIGINAL_AUD = "k58gg864hKaeLet9v7HkrFbhqsa";
    static final String ORIGINAL_EXP = "1742553132";
    static final String ORIGINAL_IAT = "1742549532";
    static final String ORIGINAL_AUTH_TIME = "1742549532";
    static final String ORIGINAL_NONCE = "abc123";

    @BeforeClass
    public void init() {

        loggerUtils = mockStatic(LoggerUtils.class);
        loggerUtils.when(LoggerUtils::isDiagnosticLogsEnabled).thenReturn(true);

        requestIDTokenBuilder = new IDToken.Builder()
                .addClaim(IDToken.ClaimNames.ISS.getName(), ORIGINAL_ISS)
                .addClaim(IDToken.ClaimNames.SUB.getName(), ORIGINAL_SUB)
                .addClaim(IDToken.ClaimNames.AUD.getName(), Arrays.asList(ORIGINAL_AUD))
                .addClaim(IDToken.ClaimNames.EXP.getName(), ORIGINAL_EXP)
                .addClaim(IDToken.ClaimNames.IAT.getName(), ORIGINAL_IAT)
                .addClaim(IDToken.ClaimNames.AUTH_TIME.getName(), ORIGINAL_AUTH_TIME)
                .addClaim(IDToken.ClaimNames.NONCE.getName(), ORIGINAL_NONCE)
                .addClaim("customClaim", "customValue");
    }

    @Test
    public void testGetSupportedActionType() {

        PreIssueIDTokenResponseProcessor processor = new PreIssueIDTokenResponseProcessor();
        assertEquals(processor.getSupportedActionType().toString(), "PRE_ISSUE_ID_TOKEN");
    }

    @Test
    public void testProcessSuccessResponse_AddClaim_Valid() throws ActionExecutionResponseProcessorException {

        List<PerformableOperation> operationsToPerform = new ArrayList<>();
        PerformableOperation addOpClaim = createPerformableOperation(Operation.ADD,
                CLAIMS_PATH_PREFIX + TAIL_CHARACTER, new IDToken.Claim("isPermanent", true));
        operationsToPerform.add(addOpClaim);

        IDTokenDTO idTokenDTO = executeProcessSuccessResponseForToken(operationsToPerform, new HashMap<>());
        assertNotNull(idTokenDTO.getCustomOIDCClaims());
        assertNotNull(idTokenDTO.getCustomOIDCClaims().get("isPermanent"));
        assertEquals(idTokenDTO.getCustomOIDCClaims().get("isPermanent"), true);
    }

    @Test
    public void testProcessSuccessResponse_AddClaim_Invalid() throws ActionExecutionResponseProcessorException {

        List<PerformableOperation> operationsToPerform = new ArrayList<>();
        operationsToPerform.add(createPerformableOperation(Operation.ADD,
                CLAIMS_PATH_PREFIX, new IDToken.Claim("isPermanent", true)));

        IDTokenDTO idTokenDTO = executeProcessSuccessResponseForToken(operationsToPerform, new HashMap<>());
        if (idTokenDTO.getCustomOIDCClaims() != null) {
            assertNull(idTokenDTO.getCustomOIDCClaims().get("isPermanent"));
        }
    }

    @Test
    public void testProcessSuccessResponse_AddAud_InvalidPath() throws ActionExecutionResponseProcessorException {

        List<PerformableOperation> operationsToPerform = new ArrayList<>();
        PerformableOperation addOpAud = createPerformableOperation(Operation.ADD,
                CLAIMS_PATH_PREFIX + IDToken.ClaimNames.AUD.getName() + "/-", "https://example.com/resource");
        operationsToPerform.add(addOpAud);

        IDTokenDTO idTokenDTO = executeProcessSuccessResponseForToken(operationsToPerform, new HashMap<>());
        assertNotNull(idTokenDTO.getAudience());
        assertEquals(idTokenDTO.getAudience().size(), 2);
        assertTrue(idTokenDTO.getAudience().contains(ORIGINAL_AUD));
        assertTrue(idTokenDTO.getAudience().contains(String.valueOf(addOpAud.getValue())));
    }

    @Test
    public void testProcessSuccessResponse_AddAud_InvalidObj() throws ActionExecutionResponseProcessorException {

        List<String> newlyAddedAUD = Arrays.asList("https://example1.com/resource", "https://example2.com/resource");

        List<PerformableOperation> operationsToPerform = new ArrayList<>();
        PerformableOperation addOpInvalidAudObj = createPerformableOperation(Operation.ADD,
                CLAIMS_PATH_PREFIX + IDToken.ClaimNames.AUD.getName() + "/-", newlyAddedAUD);
        operationsToPerform.add(addOpInvalidAudObj);

        IDTokenDTO idTokenDTO = executeProcessSuccessResponseForToken(operationsToPerform, new HashMap<>());
        assertNotNull(idTokenDTO.getAudience());
        assertEquals(idTokenDTO.getAudience().size(), 1);
        assertTrue(idTokenDTO.getAudience().contains(ORIGINAL_AUD));
    }

    @Test
    public void testProcessSuccessResponse_AddAud_AlreadyExists() throws ActionExecutionResponseProcessorException {

        List<PerformableOperation> operationsToPerform = new ArrayList<>();
        PerformableOperation addOpAud = createPerformableOperation(Operation.ADD,
                CLAIMS_PATH_PREFIX + IDToken.ClaimNames.AUD.getName() + "/-", ORIGINAL_AUD);
        operationsToPerform.add(addOpAud);

        IDTokenDTO idTokenDTO = executeProcessSuccessResponseForToken(operationsToPerform, new HashMap<>());
        assertNotNull(idTokenDTO.getAudience());
        assertEquals(idTokenDTO.getAudience().size(), 1);
        assertTrue(idTokenDTO.getAudience().contains(ORIGINAL_AUD));
    }

    @Test
    public void testProcessSuccessResponse_RemoveAud_Valid() throws ActionExecutionResponseProcessorException {

        List<PerformableOperation> operationsToPerform = new ArrayList<>();
        operationsToPerform.add(createPerformableOperation(Operation.REMOVE,
                CLAIMS_PATH_PREFIX + IDToken.ClaimNames.AUD.getName() + "/0", null));

        IDTokenDTO idTokenDTO = executeProcessSuccessResponseForToken(operationsToPerform, new HashMap<>());
        List<String> resultedAudiences = idTokenDTO.getAudience();
        assertNotNull(resultedAudiences);
        assertTrue(resultedAudiences.isEmpty());
    }

    @Test
    public void testProcessSuccessResponse_RemoveAud_Invalid() throws ActionExecutionResponseProcessorException {

        List<PerformableOperation> operationsToPerform = new ArrayList<>();
        operationsToPerform.add(createPerformableOperation(Operation.REMOVE,
                CLAIMS_PATH_PREFIX + IDToken.ClaimNames.AUD.getName() + "/", null));

        IDTokenDTO idTokenDTO = executeProcessSuccessResponseForToken(operationsToPerform, new HashMap<>());
        List<String> resultedAudiences = idTokenDTO.getAudience();
        assertFalse(CollectionUtils.isEmpty(resultedAudiences));
        assertTrue(resultedAudiences.contains(ORIGINAL_AUD));
    }

    @Test
    public void testProcessSuccessResponse_RemoveCustomClaim_Valid() throws ActionExecutionResponseProcessorException {

        List<PerformableOperation> operationsToPerform = new ArrayList<>();
        operationsToPerform.add(createPerformableOperation(Operation.REMOVE,
                CLAIMS_PATH_PREFIX + "customClaim/", null));

        IDTokenDTO idTokenDTO = executeProcessSuccessResponseForToken(operationsToPerform, new HashMap<>());
        if (idTokenDTO.getCustomOIDCClaims() != null) {
            assertNull(idTokenDTO.getCustomOIDCClaims().get("customClaim"));
        }
    }

    @DataProvider(name = "replaceAudiencesTestData")
    public Object[][] replaceAudiencesTestData() {

        return new Object[][]{
                {CLAIMS_PATH_PREFIX + IDToken.ClaimNames.AUD.getName() + "/0", "abcdefgh12345678",
                        "abcdefgh12345678"},
                {CLAIMS_PATH_PREFIX + IDToken.ClaimNames.AUD.getName() + "/-", "abcdefgh12345678",
                        "abcdefgh12345678"},
                {CLAIMS_PATH_PREFIX + IDToken.ClaimNames.AUD.getName() + "/", "abcdefgh12345678", ORIGINAL_AUD}
        };
    }

    @Test(dataProvider = "replaceAudiencesTestData")
    public void testProcessSuccessResponse_ReplaceAud(String path, String replaceableAudience, String expectedAudience)
            throws ActionExecutionResponseProcessorException {

        List<PerformableOperation> operationsToPerform = new ArrayList<>();
        operationsToPerform.add(createPerformableOperation(Operation.REPLACE, path, replaceableAudience));

        IDTokenDTO idTokenDTO = executeProcessSuccessResponseForToken(operationsToPerform, new HashMap<>());
        List<String> resultedAudiences = idTokenDTO.getAudience();
        assertNotNull(resultedAudiences);
        assertEquals(resultedAudiences.get(0), expectedAudience);
    }

    @Test
    public void testProcessSuccessResponse_ReplaceCustomClaim_Valid()
            throws ActionExecutionResponseProcessorException {

        List<PerformableOperation> operationsToPerform = new ArrayList<>();
        operationsToPerform.add(createPerformableOperation(Operation.REPLACE,
                CLAIMS_PATH_PREFIX + "customClaim", "newCustomValue"));

        Map<String, Object> existingCustomClaims = new HashMap<>();
        existingCustomClaims.put("customClaim", "customValue");
        IDTokenDTO idTokenDTO = executeProcessSuccessResponseForToken(operationsToPerform, existingCustomClaims);
        assertNotNull(idTokenDTO.getCustomOIDCClaims());
        assertNotNull(idTokenDTO.getCustomOIDCClaims().get("customClaim"));
        assertEquals(idTokenDTO.getCustomOIDCClaims().get("customClaim"), "newCustomValue");
    }

    @Test
    public void testProcessSuccessResponse_ReplaceExpiresIn_Valid()
            throws ActionExecutionResponseProcessorException {

        List<PerformableOperation> operationsToPerform = new ArrayList<>();
        long newExpiresIn = 7200L;
        operationsToPerform.add(createPerformableOperation(Operation.REPLACE,
                CLAIMS_PATH_PREFIX + IDToken.ClaimNames.EXPIRES_IN.getName(), newExpiresIn));

        IDTokenDTO idTokenDTO = executeProcessSuccessResponseForToken(operationsToPerform, new HashMap<>());
        assertEquals(idTokenDTO.getExpiresIn(), newExpiresIn * 1000);
    }

    @Test
    public void testProcessSuccessResponse_MultipleOperations() throws ActionExecutionResponseProcessorException {

        List<PerformableOperation> operationsToPerform = new ArrayList<>();

        // Add a new claim
        operationsToPerform.add(createPerformableOperation(Operation.ADD,
                CLAIMS_PATH_PREFIX + TAIL_CHARACTER, new IDToken.Claim("newClaim", "newValue")));

        // Add a new audience
        operationsToPerform.add(createPerformableOperation(Operation.ADD,
                CLAIMS_PATH_PREFIX + IDToken.ClaimNames.AUD.getName() + "/-", "https://new-audience.com"));

        IDTokenDTO idTokenDTO = executeProcessSuccessResponseForToken(operationsToPerform, new HashMap<>());

        assertNotNull(idTokenDTO.getCustomOIDCClaims());
        assertNotNull(idTokenDTO.getCustomOIDCClaims().get("newClaim"));
        assertEquals(idTokenDTO.getCustomOIDCClaims().get("newClaim"), "newValue");
        assertTrue(idTokenDTO.getAudience().contains("https://new-audience.com"));
        assertEquals(idTokenDTO.getAudience().size(), 2);
    }

    @Test
    public void testProcessSuccessResponse_TokenRequestContext() throws ActionExecutionResponseProcessorException {

        List<PerformableOperation> operationsToPerform = new ArrayList<>();
        operationsToPerform.add(createPerformableOperation(Operation.ADD,
                CLAIMS_PATH_PREFIX + TAIL_CHARACTER, new IDToken.Claim("testClaim", "testValue")));

        ActionInvocationSuccessResponse successResponse = new ActionInvocationSuccessResponse.Builder()
                .actionStatus(ActionInvocationResponse.Status.SUCCESS)
                .operations(operationsToPerform)
                .responseData(mock(ResponseData.class))
                .build();

        PreIssueIDTokenEvent.Builder preIssueIdTokenEventBuilder = new PreIssueIDTokenEvent.Builder()
                .idToken(requestIDTokenBuilder.build());
        ActionExecutionResponseContext<ActionInvocationSuccessResponse> responseContext =
                ActionExecutionResponseContext.create(preIssueIdTokenEventBuilder.build(), successResponse);

        PreIssueIDTokenResponseProcessor processor = new PreIssueIDTokenResponseProcessor();
        FlowContext flowContext = FlowContext.create();

        OAuthTokenReqMessageContext tokenMessageContext =
                new OAuthTokenReqMessageContext(new OAuth2AccessTokenReqDTO());
        IDTokenDTO idTokenDTO = new IDTokenDTO();
        idTokenDTO.setCustomOIDCClaims(new HashMap<>());
        idTokenDTO.setAudience(new ArrayList<>(Arrays.asList(ORIGINAL_AUD)));

        flowContext.add("tokenReqMessageContext", tokenMessageContext);
        flowContext.add("idTokenDTO", idTokenDTO);
        flowContext.add("requestType", "token");

        ActionExecutionStatus<Success> result = processor.processSuccessResponse(flowContext, responseContext);

        assertNotNull(result);
        assertTrue(tokenMessageContext.isPreIssueIDTokenActionsExecuted());
        assertNotNull(tokenMessageContext.getPreIssueIDTokenActionDTO());
        assertTrue(tokenMessageContext.getPreIssueIDTokenActionDTO().isPreIssueIDTokenActionExecuted());
    }

    @Test
    public void testProcessSuccessResponse_AuthzRequestContext() throws ActionExecutionResponseProcessorException {

        List<PerformableOperation> operationsToPerform = new ArrayList<>();
        operationsToPerform.add(createPerformableOperation(Operation.ADD,
                CLAIMS_PATH_PREFIX + TAIL_CHARACTER, new IDToken.Claim("testClaim", "testValue")));

        ActionInvocationSuccessResponse successResponse = new ActionInvocationSuccessResponse.Builder()
                .actionStatus(ActionInvocationResponse.Status.SUCCESS)
                .operations(operationsToPerform)
                .responseData(mock(ResponseData.class))
                .build();

        PreIssueIDTokenEvent.Builder preIssueIdTokenEventBuilder = new PreIssueIDTokenEvent.Builder()
                .idToken(requestIDTokenBuilder.build());
        ActionExecutionResponseContext<ActionInvocationSuccessResponse> responseContext =
                ActionExecutionResponseContext.create(preIssueIdTokenEventBuilder.build(), successResponse);

        PreIssueIDTokenResponseProcessor processor = new PreIssueIDTokenResponseProcessor();
        FlowContext flowContext = FlowContext.create();

        OAuthAuthzReqMessageContext authzReqMessageContext =
                new OAuthAuthzReqMessageContext(new OAuth2AuthorizeReqDTO());
        IDTokenDTO idTokenDTO = new IDTokenDTO();
        idTokenDTO.setCustomOIDCClaims(new HashMap<>());
        idTokenDTO.setAudience(new ArrayList<>(Arrays.asList(ORIGINAL_AUD)));

        flowContext.add("authzReqMessageContext", authzReqMessageContext);
        flowContext.add("idTokenDTO", idTokenDTO);
        flowContext.add("requestType", "authz");

        ActionExecutionStatus<Success> result = processor.processSuccessResponse(flowContext, responseContext);

        assertNotNull(result);
        assertTrue(authzReqMessageContext.isPreIssueIDTokenActionExecuted());
        assertNotNull(authzReqMessageContext.getPreIssueIDTokenActionDTO());
        assertTrue(authzReqMessageContext.getPreIssueIDTokenActionDTO().isPreIssueIDTokenActionExecuted());
    }

    @Test(expectedExceptions = ActionExecutionResponseProcessorException.class,
            expectedExceptionsMessageRegExp = "Invalid request type found in the flow context:.*")
    public void testProcessSuccessResponse_InvalidRequestType() throws ActionExecutionResponseProcessorException {

        List<PerformableOperation> operationsToPerform = new ArrayList<>();

        ActionInvocationSuccessResponse successResponse = new ActionInvocationSuccessResponse.Builder()
                .actionStatus(ActionInvocationResponse.Status.SUCCESS)
                .operations(operationsToPerform)
                .responseData(mock(ResponseData.class))
                .build();

        PreIssueIDTokenEvent.Builder preIssueIdTokenEventBuilder = new PreIssueIDTokenEvent.Builder()
                .idToken(requestIDTokenBuilder.build());
        ActionExecutionResponseContext<ActionInvocationSuccessResponse> responseContext =
                ActionExecutionResponseContext.create(preIssueIdTokenEventBuilder.build(), successResponse);

        PreIssueIDTokenResponseProcessor processor = new PreIssueIDTokenResponseProcessor();
        FlowContext flowContext = FlowContext.create();

        IDTokenDTO idTokenDTO = new IDTokenDTO();
        idTokenDTO.setCustomOIDCClaims(new HashMap<>());
        idTokenDTO.setAudience(new ArrayList<>(Arrays.asList(ORIGINAL_AUD)));

        flowContext.add("idTokenDTO", idTokenDTO);
        flowContext.add("requestType", "invalid");

        processor.processSuccessResponse(flowContext, responseContext);
    }

    @Test
    public void testProcessFailureResponse() throws ActionExecutionResponseProcessorException {

        String failureReason = OAuth2ErrorCodes.ACCESS_DENIED;
        String failureDescription = "Access denied by user";

        ActionInvocationFailureResponse failureResponse = new ActionInvocationFailureResponse.Builder()
                .actionStatus(ActionInvocationResponse.Status.FAILED)
                .failureReason(failureReason)
                .failureDescription(failureDescription)
                .build();

        PreIssueIDTokenEvent.Builder preIssueIdTokenEventBuilder = new PreIssueIDTokenEvent.Builder()
                .idToken(requestIDTokenBuilder.build());
        ActionExecutionResponseContext<ActionInvocationFailureResponse> responseContext =
                ActionExecutionResponseContext.create(preIssueIdTokenEventBuilder.build(), failureResponse);

        PreIssueIDTokenResponseProcessor processor = new PreIssueIDTokenResponseProcessor();
        FlowContext flowContext = FlowContext.create();

        ActionExecutionStatus<Failure> result = processor.processFailureResponse(flowContext, responseContext);

        assertNotNull(result);
        Failure failure = result.getResponse();
        assertNotNull(failure);
        assertEquals(failure.getFailureReason(), failureReason);
        assertEquals(failure.getFailureDescription(), failureDescription);
    }

    @Test(expectedExceptions = ActionExecutionResponseProcessorException.class,
            expectedExceptionsMessageRegExp = "FAILED status should not be used to process server errors.")
    public void testProcessFailureResponse_InvalidErrorCode() throws ActionExecutionResponseProcessorException {

        ActionInvocationFailureResponse failureResponse = new ActionInvocationFailureResponse.Builder()
                .actionStatus(ActionInvocationResponse.Status.FAILED)
                .failureReason(OAuth2ErrorCodes.SERVER_ERROR)
                .failureDescription("Server error occurred")
                .build();

        PreIssueIDTokenEvent.Builder preIssueIdTokenEventBuilder = new PreIssueIDTokenEvent.Builder()
                .idToken(requestIDTokenBuilder.build());
        ActionExecutionResponseContext<ActionInvocationFailureResponse> responseContext =
                ActionExecutionResponseContext.create(preIssueIdTokenEventBuilder.build(), failureResponse);

        PreIssueIDTokenResponseProcessor processor = new PreIssueIDTokenResponseProcessor();
        FlowContext flowContext = FlowContext.create();

        processor.processFailureResponse(flowContext, responseContext);
    }

    @Test
    public void testProcessErrorResponse() throws ActionExecutionResponseProcessorException {

        String errorMessage = "An error occurred during action execution";

        ActionInvocationErrorResponse errorResponse = new ActionInvocationErrorResponse.Builder()
                .actionStatus(ActionInvocationResponse.Status.ERROR)
                .errorMessage(errorMessage)
                .build();

        PreIssueIDTokenEvent.Builder preIssueIdTokenEventBuilder = new PreIssueIDTokenEvent.Builder()
                .idToken(requestIDTokenBuilder.build());
        ActionExecutionResponseContext<ActionInvocationErrorResponse> responseContext =
                ActionExecutionResponseContext.create(preIssueIdTokenEventBuilder.build(), errorResponse);

        PreIssueIDTokenResponseProcessor processor = new PreIssueIDTokenResponseProcessor();
        FlowContext flowContext = FlowContext.create();

        ActionExecutionStatus<?> result = processor.processErrorResponse(flowContext, responseContext);

        assertNotNull(result);
    }

    private PerformableOperation createPerformableOperation(Operation op, String path, Object value) {

        PerformableOperation performableOperation = new PerformableOperation();
        performableOperation.setOp(op);
        performableOperation.setPath(path);
        performableOperation.setValue(value);
        return performableOperation;
    }

    private IDTokenDTO executeProcessSuccessResponseForToken(List<PerformableOperation> operationsToPerform,
                                                             Map<String, Object> customClaims)
            throws ActionExecutionResponseProcessorException {

        ActionInvocationSuccessResponse successResponse = new ActionInvocationSuccessResponse.Builder()
                .actionStatus(ActionInvocationResponse.Status.SUCCESS)
                .operations(operationsToPerform)
                .responseData(mock(ResponseData.class))
                .build();

        PreIssueIDTokenEvent.Builder preIssueIdTokenEventBuilder = new PreIssueIDTokenEvent.Builder()
                .idToken(requestIDTokenBuilder.build());
        ActionExecutionResponseContext<ActionInvocationSuccessResponse> responseContext =
                ActionExecutionResponseContext.create(preIssueIdTokenEventBuilder.build(), successResponse);

        PreIssueIDTokenResponseProcessor processor = new PreIssueIDTokenResponseProcessor();
        FlowContext flowContext = FlowContext.create();

        OAuthTokenReqMessageContext tokenMessageContext =
                new OAuthTokenReqMessageContext(new OAuth2AccessTokenReqDTO());
        IDTokenDTO idTokenDTO = new IDTokenDTO();

        JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder();
        customClaims.forEach(jwtClaimsSetBuilder::claim);
        idTokenDTO.setIdTokenClaimsSet(jwtClaimsSetBuilder.build());
        idTokenDTO.setCustomOIDCClaims(new HashMap<>(jwtClaimsSetBuilder.build().getClaims()));
        idTokenDTO.setAudience(new ArrayList<>(Arrays.asList(ORIGINAL_AUD)));

        flowContext.add("tokenReqMessageContext", tokenMessageContext);
        flowContext.add("idTokenDTO", idTokenDTO);
        flowContext.add("requestType", "token");

        ActionExecutionStatus<Success> result = processor.processSuccessResponse(flowContext, responseContext);
        assertNotNull(result);
        assertNotNull(result.getResponseContext());

        return tokenMessageContext.getPreIssueIDTokenActionDTO();
    }

    @Test
    public void testProcessSuccessResponse_AddClaim_WithNullName() throws ActionExecutionResponseProcessorException {

        List<PerformableOperation> operationsToPerform = new ArrayList<>();
        operationsToPerform.add(createPerformableOperation(Operation.ADD,
                CLAIMS_PATH_PREFIX + TAIL_CHARACTER, new IDToken.Claim(null, "value")));

        IDTokenDTO idTokenDTO = executeProcessSuccessResponseForToken(operationsToPerform, new HashMap<>());
        assertNotNull(idTokenDTO.getCustomOIDCClaims());
        assertNull(idTokenDTO.getCustomOIDCClaims().get(null));
    }

    @Test
    public void testProcessSuccessResponse_AddClaim_WithNullValue() throws ActionExecutionResponseProcessorException {

        List<PerformableOperation> operationsToPerform = new ArrayList<>();
        operationsToPerform.add(createPerformableOperation(Operation.ADD,
                CLAIMS_PATH_PREFIX + TAIL_CHARACTER, new IDToken.Claim("testClaim", null)));

        IDTokenDTO idTokenDTO = executeProcessSuccessResponseForToken(operationsToPerform, new HashMap<>());
        assertNotNull(idTokenDTO.getCustomOIDCClaims());
        assertNull(idTokenDTO.getCustomOIDCClaims().get("testClaim"));
    }

    @Test
    public void testProcessSuccessResponse_AddClaim_StandardClaimShouldFail()
            throws ActionExecutionResponseProcessorException {

        List<PerformableOperation> operationsToPerform = new ArrayList<>();
        operationsToPerform.add(createPerformableOperation(Operation.ADD,
                CLAIMS_PATH_PREFIX + TAIL_CHARACTER, new IDToken.Claim("iss", "new-issuer")));

        IDTokenDTO idTokenDTO = executeProcessSuccessResponseForToken(operationsToPerform, new HashMap<>());
        assertNotNull(idTokenDTO.getCustomOIDCClaims());
        assertNull(idTokenDTO.getCustomOIDCClaims().get("iss"));
    }

    @Test
    public void testProcessSuccessResponse_AddClaim_AlreadyExists() throws ActionExecutionResponseProcessorException {

        List<PerformableOperation> operationsToPerform = new ArrayList<>();
        operationsToPerform.add(createPerformableOperation(Operation.ADD,
                CLAIMS_PATH_PREFIX + TAIL_CHARACTER, new IDToken.Claim("customClaim", "newValue")));

        IDTokenDTO idTokenDTO = executeProcessSuccessResponseForToken(operationsToPerform, new HashMap<>());
        assertNotNull(idTokenDTO.getCustomOIDCClaims());
        if (idTokenDTO.getCustomOIDCClaims().containsKey("customClaim")) {
            assertEquals(idTokenDTO.getCustomOIDCClaims().get("customClaim"), "customValue");
        }
    }

    @Test
    public void testProcessSuccessResponse_AddClaim_WithValidListValue()
            throws ActionExecutionResponseProcessorException {

        List<PerformableOperation> operationsToPerform = new ArrayList<>();
        List<String> listValue = Arrays.asList("value1", "value2", "value3");
        operationsToPerform.add(createPerformableOperation(Operation.ADD,
                CLAIMS_PATH_PREFIX + TAIL_CHARACTER, new IDToken.Claim("listClaim", listValue)));

        IDTokenDTO idTokenDTO = executeProcessSuccessResponseForToken(operationsToPerform, new HashMap<>());
        assertNotNull(idTokenDTO.getCustomOIDCClaims());
        assertNotNull(idTokenDTO.getCustomOIDCClaims().get("listClaim"));
        assertEquals(idTokenDTO.getCustomOIDCClaims().get("listClaim"), listValue);
    }

    @Test
    public void testProcessSuccessResponse_AddClaim_WithInvalidListValue()
            throws ActionExecutionResponseProcessorException {

        List<PerformableOperation> operationsToPerform = new ArrayList<>();
        List<Object> mixedList = Arrays.asList("value1", 123, true);
        operationsToPerform.add(createPerformableOperation(Operation.ADD,
                CLAIMS_PATH_PREFIX + TAIL_CHARACTER, new IDToken.Claim("mixedListClaim", mixedList)));

        IDTokenDTO idTokenDTO = executeProcessSuccessResponseForToken(operationsToPerform, new HashMap<>());
        assertNotNull(idTokenDTO.getCustomOIDCClaims());
        assertNull(idTokenDTO.getCustomOIDCClaims().get("mixedListClaim"));
    }

    @Test
    public void testProcessSuccessResponse_AddClaim_WithNumberValue() throws ActionExecutionResponseProcessorException {

        List<PerformableOperation> operationsToPerform = new ArrayList<>();
        operationsToPerform.add(createPerformableOperation(Operation.ADD,
                CLAIMS_PATH_PREFIX + TAIL_CHARACTER, new IDToken.Claim("numberClaim", 42)));

        IDTokenDTO idTokenDTO = executeProcessSuccessResponseForToken(operationsToPerform, new HashMap<>());
        assertNotNull(idTokenDTO.getCustomOIDCClaims());
        assertNotNull(idTokenDTO.getCustomOIDCClaims().get("numberClaim"));
        assertEquals(idTokenDTO.getCustomOIDCClaims().get("numberClaim"), 42);
    }

    @Test
    public void testProcessSuccessResponse_AddClaim_WithBooleanValue()
            throws ActionExecutionResponseProcessorException {

        List<PerformableOperation> operationsToPerform = new ArrayList<>();
        operationsToPerform.add(createPerformableOperation(Operation.ADD,
                CLAIMS_PATH_PREFIX + TAIL_CHARACTER, new IDToken.Claim("booleanClaim", false)));

        IDTokenDTO idTokenDTO = executeProcessSuccessResponseForToken(operationsToPerform, new HashMap<>());
        assertNotNull(idTokenDTO.getCustomOIDCClaims());
        assertNotNull(idTokenDTO.getCustomOIDCClaims().get("booleanClaim"));
        assertEquals(idTokenDTO.getCustomOIDCClaims().get("booleanClaim"), false);
    }

    @Test
    public void testProcessSuccessResponse_AddClaim_WithValidObjectValue()
            throws ActionExecutionResponseProcessorException {

        List<PerformableOperation> operationsToPerform = new ArrayList<>();
        Map<String, String> complexObject = new HashMap<>();
        complexObject.put("key1", "value1");
        operationsToPerform.add(createPerformableOperation(Operation.ADD,
                CLAIMS_PATH_PREFIX + TAIL_CHARACTER, new IDToken.Claim("complexClaim", complexObject)));

        IDTokenDTO idTokenDTO = executeProcessSuccessResponseForToken(operationsToPerform, new HashMap<>());
        assertNotNull(idTokenDTO.getCustomOIDCClaims());
        assertNotNull(idTokenDTO.getCustomOIDCClaims().get("complexClaim"));
        assertEquals(idTokenDTO.getCustomOIDCClaims().get("complexClaim"), complexObject);
    }

    @Test
    public void testProcessSuccessResponse_AddClaim_WithValidArrayValue()
            throws ActionExecutionResponseProcessorException {

        List<String> arrayValue = Arrays.asList("value1", "value2", "value3");
        IDToken.Claim newClaim = new IDToken.Claim("user_permissions", arrayValue);
        List<PerformableOperation> operationsToPerform = new ArrayList<>();
        operationsToPerform.add(createPerformableOperation(Operation.ADD,
                CLAIMS_PATH_PREFIX + TAIL_CHARACTER, newClaim));

        IDTokenDTO idTokenDTO = executeProcessSuccessResponseForToken(operationsToPerform, new HashMap<>());
        assertNotNull(idTokenDTO.getCustomOIDCClaims());
        assertTrue(idTokenDTO.getCustomOIDCClaims().containsKey("user_permissions"));
        Object addedValue = idTokenDTO.getCustomOIDCClaims().get("user_permissions");
        assertTrue(addedValue instanceof List, "The added claim value should be processed as a List.");

        List<?> resultedList = (List<?>) addedValue;
        assertEquals(resultedList.size(), 3);
        assertEquals(resultedList, arrayValue, "The added list elements should match the values.");
    }

    @Test
    public void testProcessSuccessResponse_AddClaim_InvalidConversion()
            throws ActionExecutionResponseProcessorException {

        List<PerformableOperation> operationsToPerform = new ArrayList<>();
        operationsToPerform.add(createPerformableOperation(Operation.ADD,
                CLAIMS_PATH_PREFIX + TAIL_CHARACTER, "invalidClaimFormat"));

        IDTokenDTO idTokenDTO = executeProcessSuccessResponseForToken(operationsToPerform, new HashMap<>());
        assertNotNull(idTokenDTO.getCustomOIDCClaims());
    }

    @Test
    public void testProcessSuccessResponse_AddAudience_WithNegativeIndex()
            throws ActionExecutionResponseProcessorException {

        List<PerformableOperation> operationsToPerform = new ArrayList<>();
        operationsToPerform.add(createPerformableOperation(Operation.ADD,
                CLAIMS_PATH_PREFIX + IDToken.ClaimNames.AUD.getName() + "/-1", "https://example.com"));

        IDTokenDTO idTokenDTO = executeProcessSuccessResponseForToken(operationsToPerform, new HashMap<>());
        assertNotNull(idTokenDTO.getAudience());
        assertEquals(idTokenDTO.getAudience().size(), 1);
    }

    @Test
    public void testProcessSuccessResponse_AddAudience_WithOutOfBoundsIndex()
            throws ActionExecutionResponseProcessorException {

        List<PerformableOperation> operationsToPerform = new ArrayList<>();
        operationsToPerform.add(createPerformableOperation(Operation.ADD,
                CLAIMS_PATH_PREFIX + IDToken.ClaimNames.AUD.getName() + "/10", "https://example.com"));

        IDTokenDTO idTokenDTO = executeProcessSuccessResponseForToken(operationsToPerform, new HashMap<>());
        assertNotNull(idTokenDTO.getAudience());
        assertEquals(idTokenDTO.getAudience().size(), 1);
    }

    @Test
    public void testProcessSuccessResponse_AddAudience_WithValidIndex()
            throws ActionExecutionResponseProcessorException {

        List<PerformableOperation> operationsToPerform = new ArrayList<>();
        operationsToPerform.add(createPerformableOperation(Operation.ADD,
                CLAIMS_PATH_PREFIX + IDToken.ClaimNames.AUD.getName() + "/0", "https://example.com"));

        IDTokenDTO idTokenDTO = executeProcessSuccessResponseForToken(operationsToPerform, new HashMap<>());
        assertNotNull(idTokenDTO.getAudience());
        assertEquals(idTokenDTO.getAudience().size(), 2);
        assertTrue(idTokenDTO.getAudience().contains("https://example.com"));
    }

    @Test
    public void testProcessSuccessResponse_AddCustomObject() throws ActionExecutionResponseProcessorException {

        Map<String, Object> orgMetadata = new HashMap<>();
        orgMetadata.put("tier", "Enterprise");
        orgMetadata.put("region", "South-East-Asia");
        orgMetadata.put("isInternal", false);

        IDToken.Claim organizationClaim = new IDToken.Claim("org_metadata", orgMetadata);
        List<PerformableOperation> operationsToPerform = new ArrayList<>();
        operationsToPerform.add(createPerformableOperation(
                Operation.ADD,
                CLAIMS_PATH_PREFIX + TAIL_CHARACTER,
                organizationClaim
        ));
        IDTokenDTO resultDTO = executeProcessSuccessResponseForToken(operationsToPerform, new HashMap<>());

        assertNotNull(resultDTO.getCustomOIDCClaims(), "The custom OIDC claims map should be initialized.");
        assertTrue(resultDTO.getCustomOIDCClaims().containsKey("org_metadata"));

        Object processedValue = resultDTO.getCustomOIDCClaims().get("org_metadata");
        assertTrue(processedValue instanceof Map, "The added claim value should be processed as a Map.");
        Map<?, ?> resultMap = (Map<?, ?>) processedValue;

        assertEquals(resultMap.get("tier"), "Enterprise");
        assertEquals(resultMap.get("region"), "South-East-Asia");
        assertEquals(resultMap.get("isInternal"), false);
    }

    @Test
    public void testProcessSuccessResponse_RemoveClaim_NotFound() throws ActionExecutionResponseProcessorException {

        List<PerformableOperation> operationsToPerform = new ArrayList<>();
        operationsToPerform.add(createPerformableOperation(Operation.REMOVE,
                CLAIMS_PATH_PREFIX + "nonExistentClaim", null));

        IDTokenDTO idTokenDTO = executeProcessSuccessResponseForToken(operationsToPerform, new HashMap<>());
        assertNotNull(idTokenDTO.getCustomOIDCClaims());
    }

    @Test
    public void testProcessSuccessResponse_RemoveClaim_FromArrayWithInvalidIndex()
            throws ActionExecutionResponseProcessorException {

        Map<String, Object> customClaims = new HashMap<>();
        customClaims.put("arrayClaim", Arrays.asList("value1", "value2"));

        List<PerformableOperation> operationsToPerform = new ArrayList<>();
        operationsToPerform.add(createPerformableOperation(Operation.REMOVE,
                CLAIMS_PATH_PREFIX + "arrayClaim/10", null));

        IDTokenDTO idTokenDTO = executeProcessSuccessResponseForToken(operationsToPerform, customClaims);
        assertNotNull(idTokenDTO.getCustomOIDCClaims());
    }

    @Test
    public void testProcessSuccessResponse_RemoveClaim_FromArrayWithNegativeIndex()
            throws ActionExecutionResponseProcessorException {

        Map<String, Object> customClaims = new HashMap<>();
        customClaims.put("arrayClaim", Arrays.asList("value1", "value2"));

        List<PerformableOperation> operationsToPerform = new ArrayList<>();
        operationsToPerform.add(createPerformableOperation(Operation.REMOVE,
                CLAIMS_PATH_PREFIX + "arrayClaim/-1", null));

        IDTokenDTO idTokenDTO = executeProcessSuccessResponseForToken(operationsToPerform, customClaims);
        assertNotNull(idTokenDTO.getCustomOIDCClaims());
    }

    @Test
    public void testProcessSuccessResponse_RemoveClaim_FromArrayWithValidIndex()
            throws ActionExecutionResponseProcessorException {

        List<String> arrayValue = new ArrayList<>(Arrays.asList("value1", "value2"));
        IDToken.Builder tokenBuilder = new IDToken.Builder()
                .addClaim(IDToken.ClaimNames.ISS.getName(), ORIGINAL_ISS)
                .addClaim(IDToken.ClaimNames.SUB.getName(), ORIGINAL_SUB)
                .addClaim(IDToken.ClaimNames.AUD.getName(), Arrays.asList(ORIGINAL_AUD))
                .addClaim(IDToken.ClaimNames.EXP.getName(), ORIGINAL_EXP)
                .addClaim(IDToken.ClaimNames.IAT.getName(), ORIGINAL_IAT)
                .addClaim("arrayClaim", arrayValue);

        List<PerformableOperation> operationsToPerform = new ArrayList<>();
        operationsToPerform.add(createPerformableOperation(Operation.REMOVE,
                CLAIMS_PATH_PREFIX + "arrayClaim/0", null));

        ActionInvocationSuccessResponse successResponse = new ActionInvocationSuccessResponse.Builder()
                .actionStatus(ActionInvocationResponse.Status.SUCCESS)
                .operations(operationsToPerform)
                .responseData(mock(ResponseData.class))
                .build();

        PreIssueIDTokenEvent.Builder preIssueIdTokenEventBuilder = new PreIssueIDTokenEvent.Builder()
                .idToken(tokenBuilder.build());
        ActionExecutionResponseContext<ActionInvocationSuccessResponse> responseContext =
                ActionExecutionResponseContext.create(preIssueIdTokenEventBuilder.build(), successResponse);

        PreIssueIDTokenResponseProcessor processor = new PreIssueIDTokenResponseProcessor();
        FlowContext flowContext = FlowContext.create();

        OAuthTokenReqMessageContext tokenMessageContext =
                new OAuthTokenReqMessageContext(new OAuth2AccessTokenReqDTO());
        IDTokenDTO idTokenDTO = new IDTokenDTO();
        Map<String, Object> customClaims = new HashMap<>();
        customClaims.put("arrayClaim", new ArrayList<>(arrayValue));
        idTokenDTO.setCustomOIDCClaims(customClaims);
        idTokenDTO.setAudience(new ArrayList<>(Arrays.asList(ORIGINAL_AUD)));

        flowContext.add("tokenReqMessageContext", tokenMessageContext);
        flowContext.add("idTokenDTO", idTokenDTO);
        flowContext.add("requestType", "token");

        processor.processSuccessResponse(flowContext, responseContext);
        IDTokenDTO resultDTO = tokenMessageContext.getPreIssueIDTokenActionDTO();
        assertNotNull(resultDTO.getCustomOIDCClaims());
        List<String> arrayClaimValue = (List<String>) resultDTO.getCustomOIDCClaims().get("arrayClaim");
        assertEquals(arrayClaimValue.size(), 1);
        assertEquals(arrayClaimValue.get(0), "value2");
    }

    @Test
    public void testProcessSuccessResponse_RemoveNestedClaim() throws ActionExecutionResponseProcessorException {

        Map<String, Object> nestedClaim = new HashMap<>();
        Map<String, Object> innerMap = new HashMap<>();
        innerMap.put("childKey", "childValue");
        nestedClaim.put("parentKey", innerMap);

        List<PerformableOperation> operationsToPerform = new ArrayList<>();
        operationsToPerform.add(createPerformableOperation(Operation.REMOVE,
                CLAIMS_PATH_PREFIX + "rootClaim/parentKey/childKey", null));
        Map<String, Object> existingClaims = new HashMap<>();
        existingClaims.put("rootClaim", nestedClaim);

        requestIDTokenBuilder.addClaim("rootClaim", nestedClaim);
        IDTokenDTO idTokenDTO = executeProcessSuccessResponseForToken(operationsToPerform, existingClaims);

        assertNotNull(idTokenDTO.getCustomOIDCClaims());
        Map<String, Object> rootClaim = (Map<String, Object>) idTokenDTO.getCustomOIDCClaims().get("rootClaim");
        Map<String, Object> parentKey = (Map<String, Object>) rootClaim.get("parentKey");

        assertFalse(parentKey.containsKey("childKey"), "Nested childKey should be removed.");
    }

    @Test
    public void testProcessSuccessResponse_RemoveGroup() throws ActionExecutionResponseProcessorException {

        List<String> initialGroupList = new ArrayList<>(Arrays.asList("value1", "value2", "value3"));
        int removalIndex = 0;

        IDToken.Builder idTokenEventBuilder = new IDToken.Builder()
                .addClaim(IDToken.ClaimNames.ISS.getName(), ORIGINAL_ISS)
                .addClaim(IDToken.ClaimNames.SUB.getName(), ORIGINAL_SUB)
                .addClaim(IDToken.ClaimNames.AUD.getName(), Arrays.asList(ORIGINAL_AUD))
                .addClaim("groups", initialGroupList);

        List<PerformableOperation> executionOperations = new ArrayList<>();
        executionOperations.add(createPerformableOperation(Operation.REMOVE,
                CLAIMS_PATH_PREFIX + "groups/" + removalIndex, null));

        ActionInvocationSuccessResponse successResponse = new ActionInvocationSuccessResponse.Builder()
                .actionStatus(ActionInvocationResponse.Status.SUCCESS)
                .operations(executionOperations)
                .responseData(mock(ResponseData.class))
                .build();
        ActionExecutionResponseContext<ActionInvocationSuccessResponse> responseContext =
                ActionExecutionResponseContext.create(new PreIssueIDTokenEvent.Builder()
                        .idToken(idTokenEventBuilder.build()).build(), successResponse);

        PreIssueIDTokenResponseProcessor processor = new PreIssueIDTokenResponseProcessor();
        FlowContext flowContext = FlowContext.create();
        OAuthTokenReqMessageContext tokenMessageContext =
                new OAuthTokenReqMessageContext(new OAuth2AccessTokenReqDTO());

        IDTokenDTO idTokenDTO = new IDTokenDTO();
        Map<String, Object> currentClaimsMap = new HashMap<>();
        currentClaimsMap.put("groups", new ArrayList<>(initialGroupList));
        idTokenDTO.setCustomOIDCClaims(currentClaimsMap);
        idTokenDTO.setAudience(new ArrayList<>(Arrays.asList(ORIGINAL_AUD)));

        flowContext.add("tokenReqMessageContext", tokenMessageContext);
        flowContext.add("idTokenDTO", idTokenDTO);
        flowContext.add("requestType", "token");
        processor.processSuccessResponse(flowContext, responseContext);

        IDTokenDTO resultDTO = tokenMessageContext.getPreIssueIDTokenActionDTO();
        List<String> updatedGroups = (List<String>) resultDTO.getCustomOIDCClaims().get("groups");

        assertNotNull(updatedGroups);
        assertEquals(updatedGroups.size(), 2);
        assertFalse(updatedGroups.contains("value1"), "Removed group should no longer be present.");
        assertTrue(updatedGroups.contains("value2"), "Remaining groups should still be present.");
    }

    @Test
    public void testProcessSuccessResponse_RemoveClaim_FromNonArrayWhenIndexProvided()
            throws ActionExecutionResponseProcessorException {

        Map<String, Object> customClaims = new HashMap<>();
        customClaims.put("stringClaim", "value");

        List<PerformableOperation> operationsToPerform = new ArrayList<>();
        operationsToPerform.add(createPerformableOperation(Operation.REMOVE,
                CLAIMS_PATH_PREFIX + "stringClaim/0", null));

        IDTokenDTO idTokenDTO = executeProcessSuccessResponseForToken(operationsToPerform, customClaims);
        assertNotNull(idTokenDTO.getCustomOIDCClaims());
    }

    @Test
    public void testProcessSuccessResponse_ReplaceExpiresIn_WithZero()
            throws ActionExecutionResponseProcessorException {

        List<PerformableOperation> operationsToPerform = new ArrayList<>();
        operationsToPerform.add(createPerformableOperation(Operation.REPLACE,
                CLAIMS_PATH_PREFIX + IDToken.ClaimNames.EXPIRES_IN.getName(), 0L));

        IDTokenDTO idTokenDTO = executeProcessSuccessResponseForToken(operationsToPerform, new HashMap<>());
        assertNotNull(idTokenDTO);
    }

    @Test
    public void testProcessSuccessResponse_ReplaceExpiresIn_WithNegativeValue()
            throws ActionExecutionResponseProcessorException {

        List<PerformableOperation> operationsToPerform = new ArrayList<>();
        operationsToPerform.add(createPerformableOperation(Operation.REPLACE,
                CLAIMS_PATH_PREFIX + IDToken.ClaimNames.EXPIRES_IN.getName(), -100L));

        IDTokenDTO idTokenDTO = executeProcessSuccessResponseForToken(operationsToPerform, new HashMap<>());
        assertNotNull(idTokenDTO);
    }

    @Test
    public void testProcessSuccessResponse_ReplaceExpiresIn_WithInvalidFormat()
            throws ActionExecutionResponseProcessorException {

        List<PerformableOperation> operationsToPerform = new ArrayList<>();
        operationsToPerform.add(createPerformableOperation(Operation.REPLACE,
                CLAIMS_PATH_PREFIX + IDToken.ClaimNames.EXPIRES_IN.getName(), "invalid"));

        IDTokenDTO idTokenDTO = executeProcessSuccessResponseForToken(operationsToPerform, new HashMap<>());
        assertNotNull(idTokenDTO);
    }

    @Test
    public void testProcessSuccessResponse_ReplaceClaim_NotFound() throws ActionExecutionResponseProcessorException {

        List<PerformableOperation> operationsToPerform = new ArrayList<>();
        operationsToPerform.add(createPerformableOperation(Operation.REPLACE,
                CLAIMS_PATH_PREFIX + "nonExistentClaim", "newValue"));

        IDTokenDTO idTokenDTO = executeProcessSuccessResponseForToken(operationsToPerform, new HashMap<>());
        assertNotNull(idTokenDTO.getCustomOIDCClaims());
    }

    @Test
    public void testProcessSuccessResponse_ReplaceClaim_InArrayWithInvalidIndex()
            throws ActionExecutionResponseProcessorException {

        Map<String, Object> customClaims = new HashMap<>();
        customClaims.put("arrayClaim", Arrays.asList("value1", "value2"));

        List<PerformableOperation> operationsToPerform = new ArrayList<>();
        operationsToPerform.add(createPerformableOperation(Operation.REPLACE,
                CLAIMS_PATH_PREFIX + "arrayClaim/10", "newValue"));

        IDTokenDTO idTokenDTO = executeProcessSuccessResponseForToken(operationsToPerform, customClaims);
        assertNotNull(idTokenDTO.getCustomOIDCClaims());
    }

    @Test
    public void testProcessSuccessResponse_ReplaceClaim_InArrayWithNegativeIndex()
            throws ActionExecutionResponseProcessorException {

        Map<String, Object> customClaims = new HashMap<>();
        customClaims.put("arrayClaim", Arrays.asList("value1", "value2"));

        List<PerformableOperation> operationsToPerform = new ArrayList<>();
        operationsToPerform.add(createPerformableOperation(Operation.REPLACE,
                CLAIMS_PATH_PREFIX + "arrayClaim/-1", "newValue"));

        IDTokenDTO idTokenDTO = executeProcessSuccessResponseForToken(operationsToPerform, customClaims);
        assertNotNull(idTokenDTO.getCustomOIDCClaims());
    }

    @Test
    public void testProcessSuccessResponse_ReplaceClaim_InArrayWithValidIndex()
            throws ActionExecutionResponseProcessorException {

        List<String> arrayValue = new ArrayList<>(Arrays.asList("value1", "value2"));
        IDToken.Builder tokenBuilder = new IDToken.Builder()
                .addClaim(IDToken.ClaimNames.ISS.getName(), ORIGINAL_ISS)
                .addClaim(IDToken.ClaimNames.SUB.getName(), ORIGINAL_SUB)
                .addClaim(IDToken.ClaimNames.AUD.getName(), Arrays.asList(ORIGINAL_AUD))
                .addClaim(IDToken.ClaimNames.EXP.getName(), ORIGINAL_EXP)
                .addClaim(IDToken.ClaimNames.IAT.getName(), ORIGINAL_IAT)
                .addClaim("arrayClaim", arrayValue);

        List<PerformableOperation> operationsToPerform = new ArrayList<>();
        operationsToPerform.add(createPerformableOperation(Operation.REPLACE,
                CLAIMS_PATH_PREFIX + "arrayClaim/0", "replacedValue"));

        ActionInvocationSuccessResponse successResponse = new ActionInvocationSuccessResponse.Builder()
                .actionStatus(ActionInvocationResponse.Status.SUCCESS)
                .operations(operationsToPerform)
                .responseData(mock(ResponseData.class))
                .build();

        PreIssueIDTokenEvent.Builder preIssueIdTokenEventBuilder = new PreIssueIDTokenEvent.Builder()
                .idToken(tokenBuilder.build());
        ActionExecutionResponseContext<ActionInvocationSuccessResponse> responseContext =
                ActionExecutionResponseContext.create(preIssueIdTokenEventBuilder.build(), successResponse);

        PreIssueIDTokenResponseProcessor processor = new PreIssueIDTokenResponseProcessor();
        FlowContext flowContext = FlowContext.create();

        OAuthTokenReqMessageContext tokenMessageContext =
                new OAuthTokenReqMessageContext(new OAuth2AccessTokenReqDTO());
        IDTokenDTO idTokenDTO = new IDTokenDTO();
        Map<String, Object> customClaims = new HashMap<>();
        customClaims.put("arrayClaim", new ArrayList<>(arrayValue));
        idTokenDTO.setCustomOIDCClaims(customClaims);
        idTokenDTO.setAudience(new ArrayList<>(Arrays.asList(ORIGINAL_AUD)));

        flowContext.add("tokenReqMessageContext", tokenMessageContext);
        flowContext.add("idTokenDTO", idTokenDTO);
        flowContext.add("requestType", "token");

        processor.processSuccessResponse(flowContext, responseContext);
        IDTokenDTO resultDTO = tokenMessageContext.getPreIssueIDTokenActionDTO();
        assertNotNull(resultDTO.getCustomOIDCClaims());
        List<String> arrayClaimValue = (List<String>) resultDTO.getCustomOIDCClaims().get("arrayClaim");
        assertTrue(arrayClaimValue.contains("replacedValue"));
        assertFalse(arrayClaimValue.contains("value1"));
    }

    @Test
    public void testProcessSuccessResponse_ReplaceClaim_InArrayWithDuplicateValue()
            throws ActionExecutionResponseProcessorException {

        Map<String, Object> customClaims = new HashMap<>();
        customClaims.put("arrayClaim", new ArrayList<>(Arrays.asList("value1", "value2")));

        List<PerformableOperation> operationsToPerform = new ArrayList<>();
        operationsToPerform.add(createPerformableOperation(Operation.REPLACE,
                CLAIMS_PATH_PREFIX + "arrayClaim/0", "value2"));

        IDTokenDTO idTokenDTO = executeProcessSuccessResponseForToken(operationsToPerform, customClaims);
        assertNotNull(idTokenDTO.getCustomOIDCClaims());
        List<String> arrayClaimValue = (List<String>) idTokenDTO.getCustomOIDCClaims().get("arrayClaim");
        assertEquals(arrayClaimValue.size(), 2);
    }

    @Test
    public void testProcessSuccessResponse_ReplaceClaim_InArrayWithInvalidPrimitiveValue()
            throws ActionExecutionResponseProcessorException {

        Map<String, Object> customClaims = new HashMap<>();
        customClaims.put("arrayClaim", Arrays.asList("value1", "value2"));

        List<PerformableOperation> operationsToPerform = new ArrayList<>();
        Map<String, String> complexValue = new HashMap<>();
        complexValue.put("key", "value");
        operationsToPerform.add(createPerformableOperation(Operation.REPLACE,
                CLAIMS_PATH_PREFIX + "arrayClaim/0", complexValue));

        IDTokenDTO idTokenDTO = executeProcessSuccessResponseForToken(operationsToPerform, customClaims);
        assertNotNull(idTokenDTO.getCustomOIDCClaims());
    }

    @Test
    public void testProcessSuccessResponse_ReplaceClaim_NonArrayWhenIndexProvided()
            throws ActionExecutionResponseProcessorException {

        Map<String, Object> customClaims = new HashMap<>();
        customClaims.put("stringClaim", "value");

        List<PerformableOperation> operationsToPerform = new ArrayList<>();
        operationsToPerform.add(createPerformableOperation(Operation.REPLACE,
                CLAIMS_PATH_PREFIX + "stringClaim/0", "newValue"));

        IDTokenDTO idTokenDTO = executeProcessSuccessResponseForToken(operationsToPerform, customClaims);
        assertNotNull(idTokenDTO.getCustomOIDCClaims());
    }

    @Test
    public void testProcessSuccessResponse_ReplaceClaim_PrimitiveClaimNotExists()
            throws ActionExecutionResponseProcessorException {

        List<PerformableOperation> operationsToPerform = new ArrayList<>();
        operationsToPerform.add(createPerformableOperation(Operation.REPLACE,
                CLAIMS_PATH_PREFIX + "nonExistentClaim", "newValue"));

        IDTokenDTO idTokenDTO = executeProcessSuccessResponseForToken(operationsToPerform, new HashMap<>());
        assertNotNull(idTokenDTO.getCustomOIDCClaims());
        assertNull(idTokenDTO.getCustomOIDCClaims().get("nonExistentClaim"));
    }

    @Test
    public void testProcessSuccessResponse_ReplaceNestedClaim() throws ActionExecutionResponseProcessorException {

        Map<String, Object> nestedClaim = new HashMap<>();
        Map<String, Object> innerMap = new HashMap<>();
        innerMap.put("targetKey", "oldValue");
        nestedClaim.put("intermediate", innerMap);

        List<PerformableOperation> operationsToPerform = new ArrayList<>();
        operationsToPerform.add(createPerformableOperation(Operation.REPLACE,
                CLAIMS_PATH_PREFIX + "complexClaim/intermediate/targetKey", "newValue"));

        Map<String, Object> existingClaims = new HashMap<>();
        existingClaims.put("complexClaim", nestedClaim);
        requestIDTokenBuilder.addClaim("complexClaim", nestedClaim);
        IDTokenDTO idTokenDTO = executeProcessSuccessResponseForToken(operationsToPerform, existingClaims);

        assertNotNull(idTokenDTO.getCustomOIDCClaims());
        Map<String, Object> complexClaim = (Map<String, Object>) idTokenDTO.getCustomOIDCClaims().get("complexClaim");
        Map<String, Object> intermediate = (Map<String, Object>) complexClaim.get("intermediate");

        assertEquals(intermediate.get("targetKey"), "newValue",
                "The nested claim value should be updated to the new value.");
    }

    @Test
    public void testProcessSuccessResponse_ReplaceGroup()
            throws ActionExecutionResponseProcessorException {

        List<String> initialGroupList = new ArrayList<>(Arrays.asList("value1", "value2", "value3"));
        String replacementValue = "NewValue";
        int targetIndex = 1;

        IDToken.Builder idTokenEventBuilder = new IDToken.Builder()
                .addClaim(IDToken.ClaimNames.ISS.getName(), ORIGINAL_ISS)
                .addClaim(IDToken.ClaimNames.SUB.getName(), ORIGINAL_SUB)
                .addClaim(IDToken.ClaimNames.AUD.getName(), Arrays.asList(ORIGINAL_AUD))
                .addClaim("groups", initialGroupList);

        List<PerformableOperation> executionOperations = new ArrayList<>();
        executionOperations.add(createPerformableOperation(Operation.REPLACE,
                CLAIMS_PATH_PREFIX + "groups/" + targetIndex, replacementValue));

        ActionInvocationSuccessResponse successResponse = new ActionInvocationSuccessResponse.Builder()
                .actionStatus(ActionInvocationResponse.Status.SUCCESS)
                .operations(executionOperations)
                .responseData(mock(ResponseData.class))
                .build();

        ActionExecutionResponseContext<ActionInvocationSuccessResponse> responseContext =
                ActionExecutionResponseContext.create(new PreIssueIDTokenEvent.Builder()
                        .idToken(idTokenEventBuilder.build()).build(), successResponse);
        PreIssueIDTokenResponseProcessor processor = new PreIssueIDTokenResponseProcessor();
        FlowContext flowContext = FlowContext.create();
        OAuthTokenReqMessageContext tokenMessageContext =
                new OAuthTokenReqMessageContext(new OAuth2AccessTokenReqDTO());

        IDTokenDTO idTokenDTO = new IDTokenDTO();
        Map<String, Object> currentClaimsMap = new HashMap<>();
        currentClaimsMap.put("groups", new ArrayList<>(initialGroupList));
        idTokenDTO.setCustomOIDCClaims(currentClaimsMap);
        idTokenDTO.setAudience(new ArrayList<>(Arrays.asList(ORIGINAL_AUD)));

        flowContext.add("tokenReqMessageContext", tokenMessageContext);
        flowContext.add("idTokenDTO", idTokenDTO);
        flowContext.add("requestType", "token");

        processor.processSuccessResponse(flowContext, responseContext);
        IDTokenDTO resultDTO = tokenMessageContext.getPreIssueIDTokenActionDTO();
        List<String> updatedGroups = (List<String>) resultDTO.getCustomOIDCClaims().get("groups");

        assertNotNull(updatedGroups);
        assertEquals(updatedGroups.size(), 3);
        assertTrue(updatedGroups.contains(replacementValue),
                "The list should contain the new value: " + replacementValue);
        assertFalse(updatedGroups.contains("value2"),
                "The list should not contain the old value.");
    }

    @Test
    public void testProcessSuccessResponse_ReplaceAudience_WithInvalidURI()
            throws ActionExecutionResponseProcessorException {

        List<PerformableOperation> operationsToPerform = new ArrayList<>();
        operationsToPerform.add(createPerformableOperation(Operation.REPLACE,
                CLAIMS_PATH_PREFIX + IDToken.ClaimNames.AUD.getName() + "/0", "invalid uri with spaces"));

        IDTokenDTO idTokenDTO = executeProcessSuccessResponseForToken(operationsToPerform, new HashMap<>());
        assertNotNull(idTokenDTO.getAudience());
        assertEquals(idTokenDTO.getAudience().get(0), ORIGINAL_AUD);
    }

    @Test
    public void testProcessSuccessResponse_ReplaceAudience_WithExistingValue()
            throws ActionExecutionResponseProcessorException {

        IDToken.Builder tokenBuilder = new IDToken.Builder()
                .addClaim(IDToken.ClaimNames.ISS.getName(), ORIGINAL_ISS)
                .addClaim(IDToken.ClaimNames.SUB.getName(), ORIGINAL_SUB)
                .addClaim(IDToken.ClaimNames.AUD.getName(), Arrays.asList(ORIGINAL_AUD, "https://another.com"))
                .addClaim(IDToken.ClaimNames.EXP.getName(), ORIGINAL_EXP)
                .addClaim(IDToken.ClaimNames.IAT.getName(), ORIGINAL_IAT);

        List<PerformableOperation> operationsToPerform = new ArrayList<>();
        operationsToPerform.add(createPerformableOperation(Operation.REPLACE,
                CLAIMS_PATH_PREFIX + IDToken.ClaimNames.AUD.getName() + "/0", "https://another.com"));

        ActionInvocationSuccessResponse successResponse = new ActionInvocationSuccessResponse.Builder()
                .actionStatus(ActionInvocationResponse.Status.SUCCESS)
                .operations(operationsToPerform)
                .responseData(mock(ResponseData.class))
                .build();

        PreIssueIDTokenEvent.Builder preIssueIdTokenEventBuilder = new PreIssueIDTokenEvent.Builder()
                .idToken(tokenBuilder.build());
        ActionExecutionResponseContext<ActionInvocationSuccessResponse> responseContext =
                ActionExecutionResponseContext.create(preIssueIdTokenEventBuilder.build(), successResponse);

        PreIssueIDTokenResponseProcessor processor = new PreIssueIDTokenResponseProcessor();
        FlowContext flowContext = FlowContext.create();

        OAuthTokenReqMessageContext tokenMessageContext =
                new OAuthTokenReqMessageContext(new OAuth2AccessTokenReqDTO());
        IDTokenDTO idTokenDTO = new IDTokenDTO();
        idTokenDTO.setCustomOIDCClaims(new HashMap<>());
        idTokenDTO.setAudience(new ArrayList<>(Arrays.asList(ORIGINAL_AUD, "https://another.com")));

        flowContext.add("tokenReqMessageContext", tokenMessageContext);
        flowContext.add("idTokenDTO", idTokenDTO);
        flowContext.add("requestType", "token");

        processor.processSuccessResponse(flowContext, responseContext);
        IDTokenDTO result = tokenMessageContext.getPreIssueIDTokenActionDTO();
        assertNotNull(result.getAudience());
    }

    @Test
    public void testProcessSuccessResponse_ReplaceAudience_WithInvalidIndex()
            throws ActionExecutionResponseProcessorException {

        List<PerformableOperation> operationsToPerform = new ArrayList<>();
        operationsToPerform.add(createPerformableOperation(Operation.REPLACE,
                CLAIMS_PATH_PREFIX + IDToken.ClaimNames.AUD.getName() + "/10", "https://example.com"));

        IDTokenDTO idTokenDTO = executeProcessSuccessResponseForToken(operationsToPerform, new HashMap<>());
        assertNotNull(idTokenDTO.getAudience());
        assertEquals(idTokenDTO.getAudience().size(), 1);
    }

    @Test
    public void testProcessSuccessResponse_WithNullOperationsListHandling()
            throws ActionExecutionResponseProcessorException {

        ActionInvocationSuccessResponse successResponse = new ActionInvocationSuccessResponse.Builder()
                .actionStatus(ActionInvocationResponse.Status.SUCCESS)
                .operations(null)
                .responseData(mock(ResponseData.class))
                .build();

        PreIssueIDTokenEvent.Builder preIssueIdTokenEventBuilder = new PreIssueIDTokenEvent.Builder()
                .idToken(requestIDTokenBuilder.build());
        ActionExecutionResponseContext<ActionInvocationSuccessResponse> responseContext =
                ActionExecutionResponseContext.create(preIssueIdTokenEventBuilder.build(), successResponse);

        PreIssueIDTokenResponseProcessor processor = new PreIssueIDTokenResponseProcessor();
        FlowContext flowContext = FlowContext.create();

        OAuthTokenReqMessageContext tokenMessageContext =
                new OAuthTokenReqMessageContext(new OAuth2AccessTokenReqDTO());
        IDTokenDTO idTokenDTO = new IDTokenDTO();
        idTokenDTO.setCustomOIDCClaims(new HashMap<>());
        idTokenDTO.setAudience(new ArrayList<>(Arrays.asList(ORIGINAL_AUD)));

        flowContext.add("tokenReqMessageContext", tokenMessageContext);
        flowContext.add("idTokenDTO", idTokenDTO);
        flowContext.add("requestType", "token");

        ActionExecutionStatus<Success> result = processor.processSuccessResponse(flowContext, responseContext);
        assertNotNull(result);
        assertTrue(tokenMessageContext.isPreIssueIDTokenActionsExecuted());
    }


    @Test
    public void testProcessSuccessResponse_EmptyOperationsList() throws ActionExecutionResponseProcessorException {

        ActionInvocationSuccessResponse successResponse = new ActionInvocationSuccessResponse.Builder()
                .actionStatus(ActionInvocationResponse.Status.SUCCESS)
                .operations(new ArrayList<>())
                .responseData(mock(ResponseData.class))
                .build();

        PreIssueIDTokenEvent.Builder preIssueIdTokenEventBuilder = new PreIssueIDTokenEvent.Builder()
                .idToken(requestIDTokenBuilder.build());
        ActionExecutionResponseContext<ActionInvocationSuccessResponse> responseContext =
                ActionExecutionResponseContext.create(preIssueIdTokenEventBuilder.build(), successResponse);

        PreIssueIDTokenResponseProcessor processor = new PreIssueIDTokenResponseProcessor();
        FlowContext flowContext = FlowContext.create();

        OAuthTokenReqMessageContext tokenMessageContext =
                new OAuthTokenReqMessageContext(new OAuth2AccessTokenReqDTO());
        IDTokenDTO idTokenDTO = new IDTokenDTO();
        idTokenDTO.setCustomOIDCClaims(new HashMap<>());
        idTokenDTO.setAudience(new ArrayList<>(Arrays.asList(ORIGINAL_AUD)));

        flowContext.add("tokenReqMessageContext", tokenMessageContext);
        flowContext.add("idTokenDTO", idTokenDTO);
        flowContext.add("requestType", "token");

        ActionExecutionStatus<Success> result = processor.processSuccessResponse(flowContext, responseContext);
        assertNotNull(result);
    }

    @Test
    public void testProcessSuccessResponse_UnsupportedPathForAddOperation()
            throws ActionExecutionResponseProcessorException {

        List<PerformableOperation> operationsToPerform = new ArrayList<>();
        operationsToPerform.add(createPerformableOperation(Operation.ADD,
                "/unsupported/path", "value"));

        IDTokenDTO idTokenDTO = executeProcessSuccessResponseForToken(operationsToPerform, new HashMap<>());
        assertNotNull(idTokenDTO);
    }

    @Test
    public void testProcessSuccessResponse_UnsupportedPathForRemoveOperation()
            throws ActionExecutionResponseProcessorException {

        List<PerformableOperation> operationsToPerform = new ArrayList<>();
        operationsToPerform.add(createPerformableOperation(Operation.REMOVE,
                "/unsupported/path", null));

        IDTokenDTO idTokenDTO = executeProcessSuccessResponseForToken(operationsToPerform, new HashMap<>());
        assertNotNull(idTokenDTO);
    }

    @Test
    public void testProcessSuccessResponse_UnsupportedPathForReplaceOperation()
            throws ActionExecutionResponseProcessorException {

        List<PerformableOperation> operationsToPerform = new ArrayList<>();
        operationsToPerform.add(createPerformableOperation(Operation.REPLACE,
                "/unsupported/path", "value"));

        IDTokenDTO idTokenDTO = executeProcessSuccessResponseForToken(operationsToPerform, new HashMap<>());
        assertNotNull(idTokenDTO);
    }

    @Test(expectedExceptions = ActionExecutionResponseProcessorException.class,
            expectedExceptionsMessageRegExp = "FAILED status should not be used to process server errors.")
    public void testProcessFailureResponse_WithInternalServerError()
            throws ActionExecutionResponseProcessorException {

        ActionInvocationFailureResponse failureResponse = new ActionInvocationFailureResponse.Builder()
                .actionStatus(ActionInvocationResponse.Status.FAILED)
                .failureReason("internal_server_error")
                .failureDescription("Internal server error occurred")
                .build();

        PreIssueIDTokenEvent.Builder preIssueIdTokenEventBuilder = new PreIssueIDTokenEvent.Builder()
                .idToken(requestIDTokenBuilder.build());
        ActionExecutionResponseContext<ActionInvocationFailureResponse> responseContext =
                ActionExecutionResponseContext.create(preIssueIdTokenEventBuilder.build(), failureResponse);

        PreIssueIDTokenResponseProcessor processor = new PreIssueIDTokenResponseProcessor();
        FlowContext flowContext = FlowContext.create();

        processor.processFailureResponse(flowContext, responseContext);
    }

    @Test(expectedExceptions = ActionExecutionResponseProcessorException.class,
            expectedExceptionsMessageRegExp = "FAILED status should not be used to process server errors.")
    public void testProcessFailureResponse_WithErrorCode500() throws ActionExecutionResponseProcessorException {

        ActionInvocationFailureResponse failureResponse = new ActionInvocationFailureResponse.Builder()
                .actionStatus(ActionInvocationResponse.Status.FAILED)
                .failureReason("500")
                .failureDescription("HTTP 500 error")
                .build();

        PreIssueIDTokenEvent.Builder preIssueIdTokenEventBuilder = new PreIssueIDTokenEvent.Builder()
                .idToken(requestIDTokenBuilder.build());
        ActionExecutionResponseContext<ActionInvocationFailureResponse> responseContext =
                ActionExecutionResponseContext.create(preIssueIdTokenEventBuilder.build(), failureResponse);

        PreIssueIDTokenResponseProcessor processor = new PreIssueIDTokenResponseProcessor();
        FlowContext flowContext = FlowContext.create();

        processor.processFailureResponse(flowContext, responseContext);
    }

    @AfterClass
    public void tearDown() {

        loggerUtils.close();
    }
}
