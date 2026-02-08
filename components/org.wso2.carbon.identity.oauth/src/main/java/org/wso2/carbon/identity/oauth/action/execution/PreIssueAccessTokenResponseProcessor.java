/*
 * Copyright (c) 2024-2025, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.oauth.action.execution;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.action.execution.api.constant.ActionExecutionLogConstants;
import org.wso2.carbon.identity.action.execution.api.exception.ActionExecutionResponseProcessorException;
import org.wso2.carbon.identity.action.execution.api.model.ActionExecutionResponseContext;
import org.wso2.carbon.identity.action.execution.api.model.ActionExecutionStatus;
import org.wso2.carbon.identity.action.execution.api.model.ActionInvocationErrorResponse;
import org.wso2.carbon.identity.action.execution.api.model.ActionInvocationFailureResponse;
import org.wso2.carbon.identity.action.execution.api.model.ActionInvocationSuccessResponse;
import org.wso2.carbon.identity.action.execution.api.model.ActionType;
import org.wso2.carbon.identity.action.execution.api.model.Error;
import org.wso2.carbon.identity.action.execution.api.model.ErrorStatus;
import org.wso2.carbon.identity.action.execution.api.model.FailedStatus;
import org.wso2.carbon.identity.action.execution.api.model.Failure;
import org.wso2.carbon.identity.action.execution.api.model.FlowContext;
import org.wso2.carbon.identity.action.execution.api.model.PerformableOperation;
import org.wso2.carbon.identity.action.execution.api.model.Success;
import org.wso2.carbon.identity.action.execution.api.model.SuccessStatus;
import org.wso2.carbon.identity.action.execution.api.service.ActionExecutionResponseProcessor;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.oauth.action.model.AbstractToken;
import org.wso2.carbon.identity.oauth.action.model.AccessToken;
import org.wso2.carbon.identity.oauth.action.model.ClaimPathInfo;
import org.wso2.carbon.identity.oauth.action.model.OperationExecutionResult;
import org.wso2.carbon.identity.oauth.action.model.PreIssueAccessTokenEvent;
import org.wso2.carbon.identity.oauth.action.model.RefreshToken;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.utils.DiagnosticLog;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * This class is responsible for processing the response received from the action execution
 * of the pre issue access token.
 */
public class PreIssueAccessTokenResponseProcessor implements ActionExecutionResponseProcessor {

    private static final Log LOG = LogFactory.getLog(PreIssueAccessTokenResponseProcessor.class);
    private static final String SCOPE_PATH_PREFIX = "/accessToken/scopes/";
    private static final String ACCESS_TOKEN_CLAIMS_PATH_PREFIX = "/accessToken/claims/";
    private static final String REFRESH_TOKEN_CLAIMS_PATH_PREFIX = "/refreshToken/claims/";
    private static final Pattern NQCHAR_PATTERN = Pattern.compile("^[\\x21\\x23-\\x5B\\x5D-\\x7E]+$");
    private static final Pattern STRING_OR_URI_PATTERN =
            Pattern.compile("^([a-zA-Z][a-zA-Z0-9+.-]*://[^\\s/$.?#].\\S*)|(^[a-zA-Z0-9.-]+$)");
    private static final String LAST_ELEMENT_CHARACTER = "-";
    private static final char PATH_SEPARATOR = '/';
    private static final String SCOPE_PROPERTY_NAME = "scope";

    @Override
    public ActionType getSupportedActionType() {

        return ActionType.PRE_ISSUE_ACCESS_TOKEN;
    }

    @Override
    public ActionExecutionStatus<Success> processSuccessResponse(FlowContext flowContext,
                                                                 ActionExecutionResponseContext
                                                                         <ActionInvocationSuccessResponse>
                                                                         responseContext)
            throws ActionExecutionResponseProcessorException {

        OAuthTokenReqMessageContext tokenMessageContext =
                flowContext.getValue("tokenMessageContext", OAuthTokenReqMessageContext.class);
        PreIssueAccessTokenEvent preIssueAccessTokenEvent = (PreIssueAccessTokenEvent) responseContext.getActionEvent();
        List<PerformableOperation> operationsToPerform = responseContext.getActionInvocationResponse().getOperations();

        AccessToken requestAccessToken = preIssueAccessTokenEvent.getAccessToken();
        AccessToken.Builder responseAccessTokenBuilder = preIssueAccessTokenEvent.getAccessToken().copy();

        Optional<RefreshToken> optionalRequestRefreshToken =
                Optional.ofNullable(preIssueAccessTokenEvent.getRefreshToken());
        Optional<RefreshToken.Builder> optionalResponseRefreshTokenBuilder =
                optionalRequestRefreshToken.map(RefreshToken::copy);

        List<OperationExecutionResult> operationExecutionResultList = new ArrayList<>();

        if (operationsToPerform != null) {
            for (PerformableOperation operation : operationsToPerform) {
                switch (operation.getOp()) {
                    case ADD:
                        operationExecutionResultList.add(
                                handleAddOperation(operation, requestAccessToken, responseAccessTokenBuilder));
                        break;
                    case REMOVE:
                        operationExecutionResultList.add(
                                handleRemoveOperation(operation, requestAccessToken, responseAccessTokenBuilder));
                        break;
                    case REPLACE:
                        operationExecutionResultList.add(
                                handleReplaceOperation(operation, requestAccessToken, responseAccessTokenBuilder));
                        optionalRequestRefreshToken.ifPresent(requestRT ->
                                optionalResponseRefreshTokenBuilder.ifPresent(
                                        responseRTBuilder -> operationExecutionResultList.add(
                                                handleReplaceOperation(operation, requestRT, responseRTBuilder))));
                        break;
                    default:
                        break;
                }
            }
        }

        logOperationExecutionResults(getSupportedActionType(), operationExecutionResultList);

        AccessToken responseAccessToken = responseAccessTokenBuilder.build();

        RefreshToken responseRefreshToken = optionalResponseRefreshTokenBuilder
                .map(RefreshToken.Builder::build)
                .orElse(null);

        updateTokenMessageContext(tokenMessageContext, responseAccessToken, responseRefreshToken);

        return new SuccessStatus.Builder().setResponseContext(flowContext.getContextData()).build();
    }

    private void logOperationExecutionResults(ActionType actionType,
                                              List<OperationExecutionResult> operationExecutionResultList) {

        if (LoggerUtils.isDiagnosticLogsEnabled()) {

            List<Map<String, String>> operationDetailsList = new ArrayList<>();
            operationExecutionResultList.forEach(performedOperation -> {
                operationDetailsList.add(Map.of(
                        "operation", performedOperation.getOperation().getOp() + " path: " +
                                performedOperation.getOperation().getPath(),
                        "status", performedOperation.getStatus().toString(),
                        "message", performedOperation.getMessage()
                ));
            });

            DiagnosticLog.DiagnosticLogBuilder diagLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                    ActionExecutionLogConstants.ACTION_EXECUTION_COMPONENT_ID,
                    ActionExecutionLogConstants.ActionIDs.PROCESS_ACTION_RESPONSE);
            diagLogBuilder
                    .inputParam("executedOperations", operationDetailsList.isEmpty() ? "empty" : operationDetailsList)
                    .resultMessage("Allowed operations are executed for " + actionType.getDisplayName() + " action.")
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                    .resultStatus(DiagnosticLog.ResultStatus.SUCCESS)
                    .build();
            LoggerUtils.triggerDiagnosticLogEvent(diagLogBuilder);
        }
        if (LOG.isDebugEnabled()) {
            ObjectMapper objectMapper = new ObjectMapper();
            objectMapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
            objectMapper.setSerializationInclusion(JsonInclude.Include.NON_EMPTY);
            try {
                String executionSummary = objectMapper.writeValueAsString(operationExecutionResultList);
                LOG.debug(String.format("Processed response for action type: %s. Results of operations performed: %s",
                        actionType, executionSummary));
            } catch (JsonProcessingException e) {
                LOG.debug("Error occurred while logging operation execution results.", e);
            }
        }
    }

    @Override
    public ActionExecutionStatus<Failure> processFailureResponse(FlowContext flowContext,
                                                                 ActionExecutionResponseContext
                                                                         <ActionInvocationFailureResponse>
                                                                         responseContext)
            throws ActionExecutionResponseProcessorException {

        ActionInvocationFailureResponse failureResponse = responseContext.getActionInvocationResponse();
        handleInvalidErrorCodes(failureResponse.getFailureReason());
        return new FailedStatus(new Failure(failureResponse.getFailureReason(),
                failureResponse.getFailureDescription()));
    }

    /**
     * This method validates the failedReason attribute in the FAILED status.
     * @param errorCode
     * @throws ActionExecutionResponseProcessorException
     */
    private void handleInvalidErrorCodes(String errorCode) throws ActionExecutionResponseProcessorException {

        // According to the current API contract server_error is considered as an invalid value for the failureReason
        // attribute.
        if (isServerError(errorCode)) {
            if (LoggerUtils.isDiagnosticLogsEnabled()) {
                DiagnosticLog.DiagnosticLogBuilder diagLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                        ActionExecutionLogConstants.ACTION_EXECUTION_COMPONENT_ID,
                        ActionExecutionLogConstants.ActionIDs.VALIDATE_ACTION_RESPONSE);
                diagLogBuilder
                        .resultMessage("Invalid value for failedReason attribute at FAILED state.")
                        .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                        .resultStatus(DiagnosticLog.ResultStatus.FAILED)
                        .build();
                LoggerUtils.triggerDiagnosticLogEvent(diagLogBuilder);
            }
            throw new ActionExecutionResponseProcessorException("FAILED status should not be used to process" +
                    " server errors.");
        }
    }

    private boolean isServerError(String errorCode) {

        return (errorCode.equalsIgnoreCase("internal_server_error") ||
                errorCode.equalsIgnoreCase("server_error") ||
                errorCode.equalsIgnoreCase(String.valueOf(HttpStatus.SC_INTERNAL_SERVER_ERROR)));
    }

    @Override
    public ActionExecutionStatus<Error> processErrorResponse(FlowContext flowContext,
                                                             ActionExecutionResponseContext
                                                                     <ActionInvocationErrorResponse> responseContext)
            throws ActionExecutionResponseProcessorException {

        /*
         * Client and server errors that occur when calling the service implementing the extension are reported
         * as Internal_Server_Error.
         * The error description could be utilized to offer additional context by passing along the
         * original error returned by the service implementing the extension.
         * However, currently this value is not propagated by the endpoint to comply with OAuth specification.
         */
        return new ErrorStatus(new Error(OAuth2ErrorCodes.SERVER_ERROR,
                responseContext.getActionInvocationResponse().getErrorDescription()));
    }

    private void updateTokenMessageContext(OAuthTokenReqMessageContext tokenMessageContext,
                                           AccessToken responseAccessToken, RefreshToken responseRefreshToken) {

        tokenMessageContext.setScope(responseAccessToken.getScopes().toArray(new String[0]));

        String expiresInClaimName = AccessToken.ClaimNames.EXPIRES_IN.getName();
        responseAccessToken.getClaims().stream()
                .filter(claim -> expiresInClaimName.equals(claim.getName()))
                .findFirst()
                .map(claim -> Long.parseLong(claim.getValue().toString()) * 1000)
                .ifPresent(tokenMessageContext::setValidityPeriod);

        if (responseRefreshToken != null) {
            String expiresInClaimNameRefreshToken = AbstractToken.ClaimNames.EXPIRES_IN.getName();
            responseRefreshToken.getClaims().stream()
                    .filter(claim -> expiresInClaimNameRefreshToken.equals(claim.getName()))
                    .findFirst()
                    .map(claim -> TimeUnit.SECONDS.toMillis(Long.parseLong(claim.getValue().toString())))
                    .ifPresent(tokenMessageContext::setRefreshTokenValidityPeriodInMillis);
        }

        Optional.ofNullable(responseAccessToken.getClaim(AccessToken.ClaimNames.AUD.getName()))
                .map(AccessToken.Claim::getValue)
                .ifPresent(value -> {
                    List<String> audienceList;
                    if (value instanceof List) {
                        audienceList = (List<String>) value;
                    } else {
                        audienceList = Collections.emptyList();
                    }
                    tokenMessageContext.setAudiences(audienceList);
                });

        Map<String, Object> customClaims = new HashMap<>();
        for (AccessToken.Claim claim : responseAccessToken.getClaims()) {
            if (!AccessToken.ClaimNames.contains(claim.getName())) {
                customClaims.put(claim.getName(), claim.getValue());
            }
        }
        tokenMessageContext.setAdditionalAccessTokenClaims(customClaims);

        tokenMessageContext.setPreIssueAccessTokenActionsExecuted(true);
    }

    private OperationExecutionResult handleAddOperation(PerformableOperation operation, AccessToken requestAccessToken,
                                                        AccessToken.Builder responseAccessToken) {

        if (operation.getPath().startsWith(SCOPE_PATH_PREFIX)) {
            return addScope(operation, responseAccessToken);
        } else if (operation.getPath().startsWith(ACCESS_TOKEN_CLAIMS_PATH_PREFIX)) {
            return addClaim(operation, requestAccessToken, responseAccessToken);
        }

        return new OperationExecutionResult(operation, OperationExecutionResult.Status.FAILURE,
                "Unknown path.");
    }

    private OperationExecutionResult addScope(PerformableOperation operation,
                                              AccessToken.Builder responseAccessToken) {

        List<String> authorizedScopes =
                responseAccessToken.getScopes() != null ? responseAccessToken.getScopes() : new ArrayList<>();

        int index = validateIndex(operation.getPath(), authorizedScopes.size());
        if (index == -1) {
            return new OperationExecutionResult(operation, OperationExecutionResult.Status.FAILURE,
                    "Invalid index.");
        }

        String scopeToAdd = operation.getValue().toString();
        if (authorizedScopes.contains(scopeToAdd) || !validateNQChar(scopeToAdd)) {
            return new OperationExecutionResult(operation, OperationExecutionResult.Status.FAILURE,
                    "Scope exists or is invalid.");
        }

        authorizedScopes.add(scopeToAdd);
        responseAccessToken.scopes(authorizedScopes);
        return new OperationExecutionResult(operation, OperationExecutionResult.Status.SUCCESS, "Scope added.");
    }

    private OperationExecutionResult addClaim(PerformableOperation operation, AccessToken requestAccessToken,
                                              AccessToken.Builder responseAccessToken) {

        List<AccessToken.Claim> claims = requestAccessToken.getClaims();

        if (claims == null || claims.isEmpty()) {
            // todo: not sure why this is here. If it's an add we don't need to check for empty claims rather just add.
            return new OperationExecutionResult(operation, OperationExecutionResult.Status.FAILURE,
                    "Claims not found.");
        }

        if (operation.getPath().startsWith(ACCESS_TOKEN_CLAIMS_PATH_PREFIX + AccessToken.ClaimNames.AUD.getName())) {
            return addAudience(operation, requestAccessToken, responseAccessToken);
        } else {
            return addToOtherClaims(operation, requestAccessToken, responseAccessToken);
        }
    }

    private OperationExecutionResult addAudience(PerformableOperation operation, AccessToken requestAccessToken,
                                                 AccessToken.Builder responseAccessToken) {

        AccessToken.Claim audience = requestAccessToken.getClaim(AccessToken.ClaimNames.AUD.getName());
        if (audience != null && audience.getValue() != null && audience.getValue() instanceof List) {
            List<String> audienceList = (List<String>) audience.getValue();

            int index = validateIndex(operation.getPath(), audienceList.size());
            if (index == -1) {
                return new OperationExecutionResult(operation, OperationExecutionResult.Status.FAILURE,
                        "Invalid index.");
            }

            String audienceToAdd = operation.getValue().toString();
            if (!isValidStringOrURI(audienceToAdd)) {
                return new OperationExecutionResult(operation, OperationExecutionResult.Status.FAILURE,
                        "Audience is invalid.");
            }

            AccessToken.Claim responseAudience =
                    responseAccessToken.getClaim(AccessToken.ClaimNames.AUD.getName());
            List<String> responseAudienceList = (List<String>) responseAudience.getValue();
            if (responseAudienceList.contains(audienceToAdd)) {
                return new OperationExecutionResult(operation, OperationExecutionResult.Status.FAILURE,
                        "Audience already exists.");
            }

            responseAudienceList.add(audienceToAdd);
            return new OperationExecutionResult(operation, OperationExecutionResult.Status.SUCCESS,
                    "Audience added.");
        }

        //todo: In the add path it should be possible to add audience irrespective of the fact the access token
        // included a set of audiences or not. Need to recheck this.
        return new OperationExecutionResult(operation, OperationExecutionResult.Status.FAILURE,
                "Audience claim not found.");
    }

    private OperationExecutionResult addToOtherClaims(PerformableOperation operation,
                                                      AccessToken requestAccessToken,
                                                      AccessToken.Builder responseAccessToken) {

        int index = validateIndex(operation.getPath(), requestAccessToken.getClaims().size());
        if (index == -1) {
            return new OperationExecutionResult(operation, OperationExecutionResult.Status.FAILURE,
                    "Invalid index.");
        }

        Object claimToAdd = operation.getValue();
        ObjectMapper objectMapper = new ObjectMapper();
        try {
            AccessToken.Claim claim = objectMapper.convertValue(claimToAdd, AccessToken.Claim.class);
            if (SCOPE_PROPERTY_NAME.equalsIgnoreCase(claim.getName())) {
                return new OperationExecutionResult(operation, OperationExecutionResult.Status.FAILURE,
                        "The operation path is invalid for the scope. Please use the path " + SCOPE_PATH_PREFIX);
            } else if (requestAccessToken.getClaim(claim.getName()) != null) {
                return new OperationExecutionResult(operation, OperationExecutionResult.Status.FAILURE,
                        "An access token claim already exists.");
            }

            Object claimValue = claim.getValue();
            if (isValidPrimitiveValue(claimValue)
                    || isValidListValue(claimValue)
                    || isValidMapValue(claimValue)) {
                responseAccessToken.addClaim(claim.getName(), claimValue);
                return new OperationExecutionResult(operation, OperationExecutionResult.Status.SUCCESS,
                        "Claim added.");
            } else {
                return new OperationExecutionResult(operation, OperationExecutionResult.Status.FAILURE,
                        "Invalid claim value.");
            }
        } catch (IllegalArgumentException e) {
            return new OperationExecutionResult(operation, OperationExecutionResult.Status.FAILURE,
                    "Invalid claim.");
        }
    }

    private OperationExecutionResult handleRemoveOperation(PerformableOperation operation,
                                                           AccessToken requestAccessToken,
                                                           AccessToken.Builder responseAccessToken) {

        if (operation.getPath().startsWith(SCOPE_PATH_PREFIX)) {
            return removeScope(operation, requestAccessToken, responseAccessToken);
        } else if (operation.getPath().startsWith(ACCESS_TOKEN_CLAIMS_PATH_PREFIX)) {
            return removeClaim(operation, requestAccessToken, responseAccessToken);
        }

        return new OperationExecutionResult(operation, OperationExecutionResult.Status.FAILURE,
                "Unknown path.");
    }

    private OperationExecutionResult removeScope(PerformableOperation operation,
                                                 AccessToken requestAccessToken,
                                                 AccessToken.Builder responseAccessToken) {

        if (requestAccessToken.getScopes() == null || requestAccessToken.getScopes().isEmpty()) {
            return new OperationExecutionResult(operation, OperationExecutionResult.Status.FAILURE,
                    "No scopes to remove.");
        }

        int index = validateIndex(operation.getPath(), requestAccessToken.getScopes().size());
        if (index == -1) {
            return new OperationExecutionResult(operation, OperationExecutionResult.Status.FAILURE,
                    "Invalid index.");
        }

        String scopeToRemove = requestAccessToken.getScopes().get(index);
        boolean removed = responseAccessToken.getScopes().remove(scopeToRemove);
        if (removed) {
            return new OperationExecutionResult(operation, OperationExecutionResult.Status.SUCCESS,
                    "Scope removed.");
        } else {
            return new OperationExecutionResult(operation, OperationExecutionResult.Status.FAILURE,
                    "Failed to remove scope.");
        }
    }

    private OperationExecutionResult removeClaim(PerformableOperation operation, AccessToken requestAccessToken,
                                                 AccessToken.Builder responseAccessToken) {

        List<AccessToken.Claim> claims = requestAccessToken.getClaims();
        if (claims == null || claims.isEmpty()) {
            return new OperationExecutionResult(operation, OperationExecutionResult.Status.FAILURE,
                    "No claims to remove.");
        }

        if (operation.getPath().startsWith(ACCESS_TOKEN_CLAIMS_PATH_PREFIX + AccessToken.ClaimNames.AUD.getName())) {
            return removeAudience(operation, requestAccessToken, responseAccessToken);
        } else {
            return removeOtherClaims(operation, requestAccessToken, responseAccessToken);
        }
    }

    private OperationExecutionResult removeAudience(PerformableOperation operation,
                                                    AccessToken requestAccessToken,
                                                    AccessToken.Builder responseAccessToken) {

        AccessToken.Claim audience = requestAccessToken.getClaim(AccessToken.ClaimNames.AUD.getName());
        if (audience != null && audience.getValue() != null && audience.getValue() instanceof List) {
            List<String> audienceList = (List<String>) audience.getValue();

            int index = validateIndex(operation.getPath(), audienceList.size());
            if (index == -1) {
                return new OperationExecutionResult(operation, OperationExecutionResult.Status.FAILURE,
                        "Invalid index.");
            }

            String audienceToRemove = audienceList.get(index);
            AccessToken.Claim responseAudience =
                    responseAccessToken.getClaim(AccessToken.ClaimNames.AUD.getName());
            List<String> responseAudienceList = (List<String>) responseAudience.getValue();
            boolean removed = responseAudienceList.remove(audienceToRemove);
            if (removed) {
                return new OperationExecutionResult(operation, OperationExecutionResult.Status.SUCCESS,
                        "Audience removed.");
            }
        }

        return new OperationExecutionResult(operation, OperationExecutionResult.Status.SUCCESS,
                "Audience not found.");
    }

    private OperationExecutionResult removeOtherClaims(PerformableOperation operation,
                                                       AccessToken requestAccessToken,
                                                       AccessToken.Builder responseAccessToken) {

        List<String> pathSegments = extractNestedClaimPath(operation.getPath());

        // nested remove
        if (pathSegments.size() > 1) {
            return removeNestedClaim(pathSegments, requestAccessToken, responseAccessToken, operation);
        }
        ClaimPathInfo claimPathInfo = parseOperationPath(operation.getPath());
        AccessToken.Claim claim = requestAccessToken.getClaim(claimPathInfo.getClaimName());

        if (claim == null) {
            return new OperationExecutionResult(operation, OperationExecutionResult.Status.FAILURE,
                    "Claim not found.");
        }

        return removePrimitiveTypeClaim(operation, claimPathInfo, responseAccessToken);
    }

    private OperationExecutionResult removeNestedClaim(List<String> pathSegments, AccessToken requestAccessToken,
                                                       AccessToken.Builder responseAccessToken,
                                                       PerformableOperation operation) {

        String rootClaimName = pathSegments.get(0);
        List<String> nestedPath = pathSegments.subList(1, pathSegments.size());

        AccessToken.Claim rootClaim = requestAccessToken.getClaim(rootClaimName);
        if (rootClaim == null || !(rootClaim.getValue() instanceof Map)) {
            return new OperationExecutionResult(operation, OperationExecutionResult.Status.FAILURE,
                    "Root claim is not a complex object.");
        }

        Map<String, Object> rootValue = new HashMap<>((Map<String, Object>) rootClaim.getValue());
        boolean removed = removeFromNestedMap(rootValue, nestedPath, 0);
        if (!removed) {
            return new OperationExecutionResult(operation, OperationExecutionResult.Status.FAILURE,
                    "Nested claim not found.");
        }

        // replace claim in response token
        responseAccessToken.getClaims().removeIf(c -> c.getName().equals(rootClaimName));
        if (!rootValue.isEmpty()) {
            responseAccessToken.addClaim(rootClaimName, rootValue);
        }

        return new OperationExecutionResult(operation, OperationExecutionResult.Status.SUCCESS,
                "Nested claim removed.");
    }

    private boolean removeFromNestedMap(Map<String, Object> current, List<String> path, int index) {

        String key = path.get(index);
        if (index == path.size() - 1) {
            return current.remove(key) != null;
        }

        Object next = current.get(key);
        if (!(next instanceof Map)) {
            return false;
        }

        return removeFromNestedMap((Map<String, Object>) next, path, index + 1);
    }

    private List<String> extractNestedClaimPath(String operationPath) {

        String relativePath = operationPath.substring(ACCESS_TOKEN_CLAIMS_PATH_PREFIX.length());
        return List.of(relativePath.split("/"));
    }

    private OperationExecutionResult removePrimitiveTypeClaim(PerformableOperation operation,
                                                              ClaimPathInfo claimPathInfo,
                                                              AccessToken.Builder responseAccessToken) {

        boolean claimRemoved =
                responseAccessToken.getClaims().removeIf(claim -> claim.getName().equals(claimPathInfo.getClaimName()));

        if (claimRemoved) {
            return new OperationExecutionResult(operation, OperationExecutionResult.Status.SUCCESS,
                    "Claim removed.");
        } else {
            return new OperationExecutionResult(operation, OperationExecutionResult.Status.FAILURE,
                    "Failed to remove claim.");
        }
    }

    private OperationExecutionResult handleReplaceOperation(PerformableOperation operation, AbstractToken token,
                                                            AbstractToken.AbstractBuilder<?> tokenBuilder) {

        if (token instanceof AccessToken) {
            if (operation.getPath().startsWith(SCOPE_PATH_PREFIX)) {
                return replaceScope(operation, (AccessToken) token, (AccessToken.Builder) tokenBuilder);
            } else if (operation.getPath().startsWith(ACCESS_TOKEN_CLAIMS_PATH_PREFIX)) {
                return replaceClaim(operation, token, tokenBuilder);
            }
        } else if (token instanceof RefreshToken && operation.getPath().startsWith(REFRESH_TOKEN_CLAIMS_PATH_PREFIX)) {
            return replaceClaim(operation, token, tokenBuilder);
        }

        return new OperationExecutionResult(operation, OperationExecutionResult.Status.FAILURE, "Unknown path.");
    }

    private OperationExecutionResult replaceScope(PerformableOperation operation, AccessToken requestAccessToken,
                                                  AccessToken.Builder responseAccessToken) {

        List<String> scopes = requestAccessToken.getScopes();
        if (scopes == null || scopes.isEmpty()) {
            return new OperationExecutionResult(operation, OperationExecutionResult.Status.FAILURE,
                    "No scopes.");
        }

        int index = validateIndex(operation.getPath(), scopes.size());
        if (index == -1) {
            return new OperationExecutionResult(operation, OperationExecutionResult.Status.FAILURE,
                    "Invalid index.");
        }

        String scopeToAdd = operation.getValue().toString();
        if (!validateNQChar(scopeToAdd)) {
            return new OperationExecutionResult(operation, OperationExecutionResult.Status.FAILURE,
                    "Invalid scope.");
        }

        if (scopes.contains(scopeToAdd)) {
            return new OperationExecutionResult(operation, OperationExecutionResult.Status.FAILURE,
                    "Scope already exists.");
        }

        String scopeToReplace = scopes.get(index);
        responseAccessToken.getScopes().remove(scopeToReplace);
        responseAccessToken.getScopes().add(scopeToAdd);
        return new OperationExecutionResult(operation, OperationExecutionResult.Status.SUCCESS, "Scope replaced.");
    }

    private OperationExecutionResult replaceClaim(PerformableOperation operation, AbstractToken token,
                                                  AbstractToken.AbstractBuilder<?> tokenBuilder) {

        List<AccessToken.Claim> claims = token.getClaims();

        if (claims == null || claims.isEmpty()) {
            return new OperationExecutionResult(operation, OperationExecutionResult.Status.FAILURE,
                    "No claims to replace.");
        }

        if (operation.getPath()
                .equals(ACCESS_TOKEN_CLAIMS_PATH_PREFIX + AbstractToken.ClaimNames.EXPIRES_IN.getName()) ||
                operation.getPath()
                        .equals(REFRESH_TOKEN_CLAIMS_PATH_PREFIX + AbstractToken.ClaimNames.EXPIRES_IN.getName())) {
            return replaceExpiresIn(operation, tokenBuilder);
        } else if (operation.getPath()
                .startsWith(ACCESS_TOKEN_CLAIMS_PATH_PREFIX + AccessToken.ClaimNames.AUD.getName())) {
            return replaceAudience(operation, (AccessToken) token,
                    (AccessToken.Builder) tokenBuilder);
        } else {
            return replaceOtherClaims(operation, token, tokenBuilder);
        }
    }

    private OperationExecutionResult replaceExpiresIn(PerformableOperation operation,
                                                      AbstractToken.AbstractBuilder<?> tokenBuilder) {

        long expiresIn;
        try {
            expiresIn = Long.parseLong(operation.getValue().toString());
        } catch (NumberFormatException e) {
            return new OperationExecutionResult(operation, OperationExecutionResult.Status.FAILURE,
                    "Invalid expiry time format.");
        }

        if (expiresIn <= 0) {
            return new OperationExecutionResult(operation, OperationExecutionResult.Status.FAILURE,
                    "Invalid expiry time. Must be positive.");
        }

        tokenBuilder.getClaims().removeIf(
                claim -> claim.getName().equals(AbstractToken.ClaimNames.EXPIRES_IN.getName()));
        tokenBuilder.addClaim(AbstractToken.ClaimNames.EXPIRES_IN.getName(), expiresIn);
        return new OperationExecutionResult(operation, OperationExecutionResult.Status.SUCCESS,
                "Expiry time updated.");
    }

    private OperationExecutionResult replaceOtherClaims(PerformableOperation operation, AbstractToken token,
                                                        AbstractToken.AbstractBuilder<?> tokenBuilder) {

        List<String> pathSegments = extractNestedClaimPath(operation.getPath());
        // nested replace
        if (pathSegments.size() > 1) {
            return replaceNestedClaim(pathSegments, token, tokenBuilder, operation);
        }

        ClaimPathInfo claimPathInfo = parseOperationPath(operation.getPath());
        AccessToken.Claim claim = token.getClaim(claimPathInfo.getClaimName());
        if (claim == null) {
            return new OperationExecutionResult(operation, OperationExecutionResult.Status.FAILURE,
                    "Claim not found.");
        }
        if (claimPathInfo.getIndex() != -1) {
            return replaceClaimValueAtIndexFromArrayTypeClaim(operation, claimPathInfo, claim, tokenBuilder);
        }

        return replacePrimitiveTypeClaim(operation, claimPathInfo, tokenBuilder);
    }

    private OperationExecutionResult replaceNestedClaim(List<String> pathSegments, AbstractToken token,
                                                        AbstractToken.AbstractBuilder<?> tokenBuilder,
                                                        PerformableOperation operation) {

        String rootClaimName = pathSegments.get(0);
        List<String> nestedPath = pathSegments.subList(1, pathSegments.size());

        AccessToken.Claim rootClaim = token.getClaim(rootClaimName);
        if (rootClaim == null || !(rootClaim.getValue() instanceof Map)) {
            return new OperationExecutionResult(operation, OperationExecutionResult.Status.FAILURE,
                    "Root claim is not a complex object.");
        }

        Map<String, Object> rootValue =
                new HashMap<>((Map<String, Object>) rootClaim.getValue());
        boolean replaced = replaceInNestedMap(rootValue, nestedPath, 0, operation.getValue());
        if (!replaced) {
            return new OperationExecutionResult(operation, OperationExecutionResult.Status.FAILURE,
                    "Nested claim not found.");
        }

        tokenBuilder.getClaims().removeIf(c -> c.getName().equals(rootClaimName));
        if (!rootValue.isEmpty()) {
            tokenBuilder.addClaim(rootClaimName, rootValue);
        }

        return new OperationExecutionResult(operation, OperationExecutionResult.Status.SUCCESS,
                "Nested claim replaced.");
    }

    private boolean replaceInNestedMap(Map<String, Object> current, List<String> path, int index, Object newValue) {

        String key = path.get(index);

        if (index == path.size() - 1) {
            if (newValue == null) {
                return current.remove(key) != null;
            }
            current.put(key, newValue);
            return true;
        }

        Object next = current.get(key);
        if (!(next instanceof Map)) {
            return false;
        }
        boolean updated = replaceInNestedMap((Map<String, Object>) next, path, index + 1, newValue);
        Map<String, Object> nextMap = (Map<String, Object>) next;
        if (updated && nextMap.isEmpty()) {
            current.remove(key);
        }

        return updated;
    }

    private OperationExecutionResult replaceClaimValueAtIndexFromArrayTypeClaim(PerformableOperation operation,
                                                                                ClaimPathInfo claimPathInfo,
                                                                                AccessToken.Claim claim,
                                                                                AbstractToken.AbstractBuilder<?>
                                                                                        responseAccessToken) {

        if (!(claim.getValue() instanceof List)) {
            return new OperationExecutionResult(operation, OperationExecutionResult.Status.FAILURE,
                    "Claim to replace the value is not an array.");
        }

        List<String> claimValueList = (List<String>) claim.getValue();
        if (claimPathInfo.getIndex() < 0 || claimPathInfo.getIndex() >= claimValueList.size()) {
            return new OperationExecutionResult(operation, OperationExecutionResult.Status.FAILURE, "Invalid index.");
        }

        Object claimValue = operation.getValue();
        if (!isValidPrimitiveValue(claimValue)) {
            return new OperationExecutionResult(operation, OperationExecutionResult.Status.FAILURE,
                    "Invalid claim value. Must be a valid string, number or boolean.");
        }

        // Replace claim value in the response access token
        AccessToken.Claim claimInResponse = responseAccessToken.getClaim(claimPathInfo.getClaimName());
        List<String> claimValueListInResponse = (List<String>) claimInResponse.getValue();
        String claimToReplace = claimValueList.get(claimPathInfo.getIndex());
        if (claimValueListInResponse.contains(claimValue.toString())) {
            return new OperationExecutionResult(operation, OperationExecutionResult.Status.FAILURE,
                    "Claim value already exists.");
        }
        claimValueListInResponse.remove(claimToReplace);
        claimValueListInResponse.add(claimValue.toString());
        return new OperationExecutionResult(operation, OperationExecutionResult.Status.SUCCESS,
                "Claim value replaced.");
    }

    private OperationExecutionResult replacePrimitiveTypeClaim(PerformableOperation operation,
                                                               ClaimPathInfo claimPathInfo,
                                                               AbstractToken.AbstractBuilder<?> responseAccessToken) {

        boolean claimRemoved = responseAccessToken.getClaims()
                .removeIf(claim -> claim.getName().equals(claimPathInfo.getClaimName()));
        if (claimRemoved) {
            responseAccessToken.addClaim(claimPathInfo.getClaimName(),
                    operation.getValue());
            return new OperationExecutionResult(operation, OperationExecutionResult.Status.SUCCESS,
                    "Claim replaced.");
        } else {
            return new OperationExecutionResult(operation, OperationExecutionResult.Status.FAILURE,
                    "Failed to replace claim.");
        }
    }

    private OperationExecutionResult replaceAudience(PerformableOperation operation, AccessToken
            requestAccessToken,
                                                     AccessToken.Builder responseAccessToken) {

        AccessToken.Claim audience = requestAccessToken.getClaim(AccessToken.ClaimNames.AUD.getName());
        if (audience != null && audience.getValue() != null && audience.getValue() instanceof List) {
            List<String> audienceList = (List<String>) audience.getValue();

            int index = validateIndex(operation.getPath(), audienceList.size());
            if (index == -1) {
                return new OperationExecutionResult(operation, OperationExecutionResult.Status.FAILURE,
                        "Invalid index.");
            }

            String audienceToAdd = operation.getValue().toString();
            if (!isValidStringOrURI(audienceToAdd)) {
                return new OperationExecutionResult(operation, OperationExecutionResult.Status.FAILURE,
                        "Invalid Audience. Must be a valid string or URI.");
            }

            if (audienceList.contains(audienceToAdd)) {
                return new OperationExecutionResult(operation, OperationExecutionResult.Status.FAILURE,
                        "Audience to replace already exists.");
            }

            String audienceToReplace = audienceList.get(index);

            AccessToken.Claim responseAudience =
                    responseAccessToken.getClaim(AccessToken.ClaimNames.AUD.getName());
            List<String> responseAudienceList = (List<String>) responseAudience.getValue();
            responseAudienceList.remove(audienceToReplace);
            responseAudienceList.add(audienceToAdd);
            return new OperationExecutionResult(operation, OperationExecutionResult.Status.SUCCESS,
                    "Audience replaced.");
        }

        return new OperationExecutionResult(operation, OperationExecutionResult.Status.FAILURE,
                "Audience claim not found.");
    }

    private ClaimPathInfo parseOperationPath(String operationPath) {

        String[] pathSegments = operationPath.split("/");
        String lastSegment = pathSegments[pathSegments.length - 1];
        String claimName;
        int index = -1;

        try {
            // Attempt to parse the last segment as an integer to check if it's an index
            index = Integer.parseInt(lastSegment);
            // If parsing succeeds, the last segment is an index, so the claim name is the second last segment
            claimName = pathSegments[pathSegments.length - 2];
        } catch (NumberFormatException e) {
            // If parsing fails, the last segment is not an index, so it's the claim name itself
            claimName = lastSegment;
        }

        return new ClaimPathInfo(claimName, index);
    }

    private boolean isValidPrimitiveValue(Object value) {

        return value instanceof String || value instanceof Number || value instanceof Boolean;
    }

    private boolean isValidListValue(Object value) {

        if (!(value instanceof List<?>)) {
            return false;
        }
        List<?> list = (List<?>) value;
        return list.stream().allMatch(item -> item instanceof String);
    }

    private boolean isValidMapValue(Object value) {

        if (!(value instanceof Map<?, ?>)) {
            return false;
        }
        Map<?, ?> map = (Map<?, ?>) value;
        return true;
    }

    private int validateIndex(String operationPath, int listSize) {

        String indexPart = operationPath.substring(operationPath.lastIndexOf(PATH_SEPARATOR) + 1);
        if (LAST_ELEMENT_CHARACTER.equals(indexPart)) {
            return listSize > 0 ? listSize - 1 : 0;
        }

        try {
            int index = Integer.parseInt(indexPart);
            if (index >= 0 && index < listSize) {
                return index;
            } else {
                LOG.info("Index is out of bounds: " + indexPart);
                return -1;
            }
        } catch (NumberFormatException ignored) {
            LOG.info("Extracted index is not a valid integer. Index: " + indexPart);
        }

        LOG.info("Invalid index: " + indexPart);
        return -1;
    }

    private boolean validateNQChar(String input) {

        Matcher matcher = NQCHAR_PATTERN.matcher(input);
        return matcher.matches();
    }

    private boolean isValidStringOrURI(String input) {

        Matcher matcher = STRING_OR_URI_PATTERN.matcher(input);
        return matcher.matches();
    }
}
