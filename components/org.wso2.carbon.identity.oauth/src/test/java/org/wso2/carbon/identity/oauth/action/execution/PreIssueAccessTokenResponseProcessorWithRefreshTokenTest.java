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
import org.wso2.carbon.identity.oauth.action.model.RefreshToken;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;

import java.util.ArrayList;
import java.util.List;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;
import static org.wso2.carbon.identity.oauth.action.execution.PreIssueAccessTokenRequestBuilder.ACCESS_TOKEN_CLAIMS_PATH_PREFIX;
import static org.wso2.carbon.identity.oauth.action.execution.PreIssueAccessTokenRequestBuilder.REFRESH_TOKEN_CLAIMS_PATH_PREFIX;

public class PreIssueAccessTokenResponseProcessorWithRefreshTokenTest {

    private AccessToken.Builder requestAccessTokenBuilder;
    private RefreshToken.Builder requestRefreshTokenBuilder;
    private MockedStatic<LoggerUtils> loggerUtils;

    static final String ORIGINAL_ISS = "https://localhost:9443/oauth2/token";
    static final String ORIGINAL_SUB = "3da43e1c-4087-46e2-ad46-08ccc76bf616";
    static final String ORIGINAL_AUD = "k58gg864hKaeLet9v7HkrFbhqsa";
    static final String ORIGINAL_ACCESS_TOKEN_EXPIRE_IN = "3600";
    static final String ORIGINAL_REFRESH_TOKEN_EXPIRE_IN = "86400";
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
                .addClaim(AccessToken.ClaimNames.EXPIRES_IN.getName(), ORIGINAL_ACCESS_TOKEN_EXPIRE_IN)
                .addClaim(AccessToken.ClaimNames.CLIENT_ID.getName(), ORIGINAL_CLIENT_ID)
                .addClaim(AccessToken.ClaimNames.AUTHORIZED_USER_TYPE.getName(), ORIGINAL_APPLICATION_USER)
                .addClaim("CustomClaimName", "CustomClaim")
                .addScope(ORIGINAL_SCOPES[0])
                .addScope(ORIGINAL_SCOPES[1])
                .addScope(ORIGINAL_SCOPES[2]);

        requestRefreshTokenBuilder = new RefreshToken.Builder()
                .addClaim(RefreshToken.ClaimNames.EXPIRES_IN.getName(), ORIGINAL_REFRESH_TOKEN_EXPIRE_IN);
    }

    private PerformableOperation createPerformableOperation(Operation op, String path, Object value) {

        PerformableOperation performableOperation = new PerformableOperation();
        performableOperation.setOp(op);
        performableOperation.setPath(path);
        performableOperation.setValue(value);
        return performableOperation;
    }

    @Test
    void testProcessSuccessResponseAddAudInvalidPath() throws ActionExecutionResponseProcessorException {

        List<PerformableOperation> operationsToPerform = new ArrayList<>();
        PerformableOperation addOpAud = createPerformableOperation(Operation.ADD,
                ACCESS_TOKEN_CLAIMS_PATH_PREFIX + AccessToken.ClaimNames.AUD.getName() + "/-",
                "https://example.com/resource");
        operationsToPerform.add(addOpAud);

        OAuthTokenReqMessageContext oAuthTokenReqMessageContext = executeProcessSuccessResponse(operationsToPerform);

        assertNull(oAuthTokenReqMessageContext.getAdditionalAccessTokenClaims().get("aud"));
        assertEquals(oAuthTokenReqMessageContext.getAudiences().size(), 2);
        assertTrue(oAuthTokenReqMessageContext.getAudiences().contains(ORIGINAL_AUD));
        assertTrue(oAuthTokenReqMessageContext.getAudiences().contains(String.valueOf(addOpAud.getValue())));
    }

    @Test
    void testProcessSuccessResponseAddClaimInvalid() throws ActionExecutionResponseProcessorException {

        List<PerformableOperation> operationsToPerform = new ArrayList<>();
        operationsToPerform.add(createPerformableOperation(Operation.ADD,
                ACCESS_TOKEN_CLAIMS_PATH_PREFIX, new AccessToken.Claim("isPermanent", true)));

        OAuthTokenReqMessageContext oAuthTokenReqMessageContext = executeProcessSuccessResponse(operationsToPerform);

        assertNull(oAuthTokenReqMessageContext.getAdditionalAccessTokenClaims().get("isPermanent"));
    }

    @DataProvider(name = "replaceExpireInTestData")
    public Object[][] replaceExpireInTestData() {

        return new Object[][]{
                {REFRESH_TOKEN_CLAIMS_PATH_PREFIX + RefreshToken.ClaimNames.EXPIRES_IN.getName(), 1000, 1000000},
                {REFRESH_TOKEN_CLAIMS_PATH_PREFIX + RefreshToken.ClaimNames.EXPIRES_IN.getName() + "/", 2000, 2000000}
        };
    }

    @Test(dataProvider = "replaceExpireInTestData")
    void testProcessSuccessResponseReplaceExpireInValid(String path, long replaceableExpireIn, long expectedExpireIn)
            throws ActionExecutionResponseProcessorException {

        List<PerformableOperation> operationsToPerform = new ArrayList<>();
        operationsToPerform.add(createPerformableOperation(Operation.REPLACE,
                path, replaceableExpireIn));

        OAuthTokenReqMessageContext oAuthTokenReqMessageContext = executeProcessSuccessResponse(operationsToPerform);
        // Get the validity period in milliseconds
        long validityPeriod = oAuthTokenReqMessageContext.getRefreshTokenValidityPeriodInMillis();
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
                .accessToken(requestAccessTokenBuilder.build()).refreshToken(requestRefreshTokenBuilder.build());
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
