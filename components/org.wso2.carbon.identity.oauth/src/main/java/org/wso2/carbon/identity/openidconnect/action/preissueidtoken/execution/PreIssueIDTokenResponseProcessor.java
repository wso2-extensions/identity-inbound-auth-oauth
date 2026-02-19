/*
 * Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.openidconnect.action.preissueidtoken.execution;

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
import org.wso2.carbon.identity.oauth.action.model.AccessToken;
import org.wso2.carbon.identity.oauth.action.model.ClaimPathInfo;
import org.wso2.carbon.identity.oauth.action.model.OperationExecutionResult;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.openidconnect.action.preissueidtoken.dto.IDTokenDTO;
import org.wso2.carbon.identity.openidconnect.action.preissueidtoken.model.IDToken;
import org.wso2.carbon.identity.openidconnect.action.preissueidtoken.model.PreIssueIDTokenEvent;
import org.wso2.carbon.utils.DiagnosticLog;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * This class is responsible for processing the response received from the action execution
 * of the pre issue id token.
 */
public class PreIssueIDTokenResponseProcessor implements ActionExecutionResponseProcessor {

    private static final Log LOG = LogFactory.getLog(PreIssueIDTokenResponseProcessor.class);
    private static final String TOKEN_REQUEST_MESSAGE_CONTEXT = "tokenReqMessageContext";
    private static final String AUTHZ_REQUEST_MESSAGE_CONTEXT = "authzReqMessageContext";
    private static final String ID_TOKEN_DTO = "idTokenDTO";
    private static final String REQUEST_TYPE = "requestType";
    private static final String REQUEST_TYPE_TOKEN = "token";
    private static final String REQUEST_TYPE_AUTHZ = "authz";
    private static final String CLAIMS_PATH_PREFIX = "/idToken/claims/";
    private static final String LAST_ELEMENT_CHARACTER = "-";
    private static final char PATH_SEPARATOR = '/';
    private static final Pattern STRING_OR_URI_PATTERN =
            Pattern.compile("^([a-zA-Z][a-zA-Z0-9+.-]*://[^\\s/$.?#].\\S*)|(^[a-zA-Z0-9.-]+$)");
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public ActionType getSupportedActionType() {

        return ActionType.PRE_ISSUE_ID_TOKEN;
    }

    @Override
    public ActionExecutionStatus<Success> processSuccessResponse(FlowContext flowContext,
                                                                 ActionExecutionResponseContext
                                                                         <ActionInvocationSuccessResponse>
                                                                         actionExecutionResponseContext)
            throws ActionExecutionResponseProcessorException {


        IDTokenDTO idTokenDTO = flowContext.getValue(ID_TOKEN_DTO, IDTokenDTO.class);

        PreIssueIDTokenEvent preIssueIdTokenEvent = (PreIssueIDTokenEvent)
                actionExecutionResponseContext.getActionEvent();
        List<PerformableOperation> operationsToPerform =
                actionExecutionResponseContext.getActionInvocationResponse().getOperations();

        IDToken requestedIDToken = preIssueIdTokenEvent.getIdToken();
        List<OperationExecutionResult> operationExecutionResultList = new ArrayList<>();

        if (operationsToPerform != null && !operationsToPerform.isEmpty()) {
            for (PerformableOperation operation : operationsToPerform) {

                switch (operation.getOp()) {
                    case ADD:
                        operationExecutionResultList.add(
                                handleAddOperation(operation, requestedIDToken, idTokenDTO));
                        break;
                    case REMOVE:
                        operationExecutionResultList.add(
                                handleRemoveOperation(operation, requestedIDToken, idTokenDTO));
                        break;
                    case REPLACE:
                        operationExecutionResultList.add(
                                handleReplaceOperation(operation, requestedIDToken, idTokenDTO));
                        break;
                    default:
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("Unsupported operation type: " + operation.getOp() +
                                    " in Pre Issue ID Token action.");
                        }
                        break;
                }
            }
        }

        logOperationExecutionResults(getSupportedActionType(), operationExecutionResultList);

        String tokenType = flowContext.getValue(REQUEST_TYPE, String.class);

        if (REQUEST_TYPE_TOKEN.equals(tokenType)) {
            OAuthTokenReqMessageContext tokenMessageContext =
                    flowContext.getValue(TOKEN_REQUEST_MESSAGE_CONTEXT, OAuthTokenReqMessageContext.class);
            updateTokenMessageContext(tokenMessageContext, idTokenDTO);
        } else if (REQUEST_TYPE_AUTHZ.equals(tokenType)) {
            OAuthAuthzReqMessageContext authzReqMessageContext =
                    flowContext.getValue(AUTHZ_REQUEST_MESSAGE_CONTEXT, OAuthAuthzReqMessageContext.class);
            updateAuthzMessageContext(authzReqMessageContext, idTokenDTO);
        } else {
            throw new ActionExecutionResponseProcessorException("Invalid request type found in the flow context: "
                    + tokenType);
        }

        return new SuccessStatus.Builder().setResponseContext(flowContext.getContextData()).build();

    }

    private void updateTokenMessageContext(OAuthTokenReqMessageContext tokenMessageContext,
                                           IDTokenDTO idTokenDTO) {

        idTokenDTO.setPreIssueIDTokenActionExecuted(true);
        tokenMessageContext.setPreIssueIDTokenActionsExecuted(true);
        tokenMessageContext.setPreIssueIDTokenActionDTO(idTokenDTO);
    }

    private void updateAuthzMessageContext(OAuthAuthzReqMessageContext authzReqMessageContext,
                                           IDTokenDTO idTokenDTO) {

        idTokenDTO.setPreIssueIDTokenActionExecuted(true);
        authzReqMessageContext.setPreIssueIDTokenActionExecuted(true);
        authzReqMessageContext.setPreIssueIDTokenActionDTO(idTokenDTO);
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

    private OperationExecutionResult handleAddOperation(PerformableOperation operation, IDToken requestIDToken,
                                                       IDTokenDTO responseIDTokenDTO) {

        if (operation.getPath().startsWith(CLAIMS_PATH_PREFIX)) {
            return addClaim(operation, requestIDToken, responseIDTokenDTO);
        }

        return new OperationExecutionResult(operation, OperationExecutionResult.Status.FAILURE,
                "Unsupported path for ADD operation: " + operation.getPath());
    }

    private OperationExecutionResult addClaim(PerformableOperation operation,
                                              IDToken requestIDToken,
                                              IDTokenDTO responseIDTokenDTO) {

        if (operation.getPath().startsWith(CLAIMS_PATH_PREFIX + IDToken.ClaimNames.AUD.getName())) {
            return addAudience(operation, requestIDToken, responseIDTokenDTO);
        }
        return addToOtherClaims(operation, requestIDToken, responseIDTokenDTO);
    }

    private OperationExecutionResult addAudience(PerformableOperation operation,
                                                 IDToken requestIDToken,
                                                 IDTokenDTO responseIDTokenDTO) {

        AccessToken.Claim audience = requestIDToken.getClaim(IDToken.ClaimNames.AUD.getName());
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

            List<String> responseAudienceList = responseIDTokenDTO.getAudience();

            if (responseAudienceList.contains(audienceToAdd)) {
                return new OperationExecutionResult(operation, OperationExecutionResult.Status.FAILURE,
                        "Audience already exists.");
            }

            responseAudienceList.add(audienceToAdd);
            return new OperationExecutionResult(operation, OperationExecutionResult.Status.SUCCESS,
                    "Audience added.");
        }

        return new OperationExecutionResult(operation, OperationExecutionResult.Status.FAILURE,
                "Audience claim not found.");
    }

    private OperationExecutionResult addToOtherClaims(PerformableOperation operation,
                                                      IDToken requestIDToken,
                                                      IDTokenDTO responseIDTokenDTO) {

        int index = validateIndex(operation.getPath(), requestIDToken.getClaims().size());
        if (index == -1) {
            return new OperationExecutionResult(operation, OperationExecutionResult.Status.FAILURE,
                    "Invalid index.");
        }

        Object claimToAdd = operation.getValue();
        try {
            IDToken.Claim claim = objectMapper.convertValue(claimToAdd, IDToken.Claim.class);
            if (claim.getName() == null || claim.getValue() == null) {
                return new OperationExecutionResult(operation, OperationExecutionResult.Status.FAILURE,
                        "Claim name or value cannot be null.");
            } else if (IDToken.ClaimNames.contains(claim.getName())) {
                return new OperationExecutionResult(operation, OperationExecutionResult.Status.FAILURE,
                        "Cannot add standard claim '" + claim.getName() + "' to ID Token.");
            } else if (requestIDToken.getClaim(claim.getName()) != null) {
                return new OperationExecutionResult(operation, OperationExecutionResult.Status.FAILURE,
                        "Claim with name '" + claim.getName() + "' already exists in ID Token.");
            }

            Object claimValue = claim.getValue();
            if (isValidPrimitiveValue(claimValue)
                    || isValidListValue(claimValue)
                    || isValidMapValue(claimValue)) {
                responseIDTokenDTO.getCustomOIDCClaims().put(claim.getName(), claim.getValue());
                return new OperationExecutionResult(operation, OperationExecutionResult.Status.SUCCESS, "Claim added.");
            } else {
                return new OperationExecutionResult(operation, OperationExecutionResult.Status.FAILURE,
                        "Invalid claim value.");
            }
        } catch (IllegalArgumentException e) {
            LOG.error("Failed to convert the value to Claim object for ADD operation.", e);
            return new OperationExecutionResult(operation, OperationExecutionResult.Status.FAILURE,
                    "Failed to convert the value to Claim object.");
        }
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

    private OperationExecutionResult handleRemoveOperation(PerformableOperation operation, IDToken requestedIDToken,
                                                          IDTokenDTO responseIDTokenDTO) {

        if (operation.getPath().startsWith(CLAIMS_PATH_PREFIX)) {
            return removeClaim(operation, requestedIDToken, responseIDTokenDTO);
        }
        return new OperationExecutionResult(operation, OperationExecutionResult.Status.FAILURE,
                "Unsupported path for REMOVE operation: " + operation.getPath());
    }

    private OperationExecutionResult removeClaim(PerformableOperation operation, IDToken requestIDToken,
                                                 IDTokenDTO responseIDTokenDTO) {

        if (operation.getPath().startsWith(CLAIMS_PATH_PREFIX + IDToken.ClaimNames.AUD.getName())) {
            return removeAudience(operation, requestIDToken, responseIDTokenDTO);
        }
        return removeOtherClaims(operation, requestIDToken, responseIDTokenDTO);

    }

    private OperationExecutionResult removeAudience(PerformableOperation operation,
                                                    IDToken requestIDToken,
                                                    IDTokenDTO responseIDTokenDTO) {

        IDToken.Claim audience = requestIDToken.getClaim(IDToken.ClaimNames.AUD.getName());
        if (audience != null && audience.getValue() != null && audience.getValue() instanceof List) {
            List<String> audienceList = (List<String>) audience.getValue();

            int index = validateIndex(operation.getPath(), audienceList.size());
            if (index == -1) {
                return new OperationExecutionResult(operation, OperationExecutionResult.Status.FAILURE,
                        "Invalid index.");
            }

            String audienceToRemove = audienceList.get(index);
            List<String> responseAudienceList =
                    responseIDTokenDTO.getAudience();

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
                                                       IDToken requestIDToken,
                                                       IDTokenDTO responseIDTokenDTO) {

        List<String> pathSegments = extractNestedClaimPath(operation.getPath());

        // Nested removal
        if (pathSegments.size() > 1 && !isArrayIndexPath(pathSegments)) {
            return removeNestedClaim(pathSegments, requestIDToken, responseIDTokenDTO, operation);
        }

        ClaimPathInfo claimPathInfo = parseOperationPath(operation.getPath());
        IDToken.Claim claim = requestIDToken.getClaim(claimPathInfo.getClaimName());
        if (claim == null) {
            return new OperationExecutionResult(operation, OperationExecutionResult.Status.FAILURE,
                    "Claim not found.");
        }

        if (claimPathInfo.getIndex() != -1) {
            return removeClaimValueAtIndexFromArrayTypeClaim(operation, claimPathInfo, claim,
                    responseIDTokenDTO);
        } else {
            return removePrimitiveTypeClaim(operation, claimPathInfo, responseIDTokenDTO);
        }
    }

    private OperationExecutionResult removeNestedClaim(List<String> pathSegments, IDToken requestIDToken,
                                                       IDTokenDTO responseIDTokenDTO,
                                                       PerformableOperation operation) {

        String rootClaimName = pathSegments.get(0);
        List<String> nestedPath = pathSegments.subList(1, pathSegments.size());

        IDToken.Claim rootClaim = requestIDToken.getClaim(rootClaimName);
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

        if (rootValue.isEmpty()) {
            responseIDTokenDTO.getCustomOIDCClaims().remove(rootClaimName);
        } else {
            responseIDTokenDTO.getCustomOIDCClaims().put(rootClaimName, rootValue);
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

        String relativePath = operationPath.substring(CLAIMS_PATH_PREFIX.length());
        return List.of(relativePath.split("/"));
    }

    private OperationExecutionResult removeClaimValueAtIndexFromArrayTypeClaim(PerformableOperation operation,
                                                                               ClaimPathInfo claimPathInfo,
                                                                               IDToken.Claim claim,
                                                                               IDTokenDTO
                                                                                       responseIDTokenDTO) {

        if (!(claim.getValue() instanceof List)) {
            return new OperationExecutionResult(operation, OperationExecutionResult.Status.FAILURE,
                    "Claim to remove the value from is not an array.");
        }

        List<String> claimValueList = (List<String>) claim.getValue();
        if (claimPathInfo.getIndex() < 0 || claimPathInfo.getIndex() >= claimValueList.size()) {
            return new OperationExecutionResult(operation, OperationExecutionResult.Status.FAILURE,
                    "Invalid index.");
        }

        String claimValueToRemove = claimValueList.get(claimPathInfo.getIndex());

        Object claimInResponse =
                responseIDTokenDTO.getCustomOIDCClaims().get(claimPathInfo.getClaimName());
        List<String> claimValueListInResponse = (List<String>) claimInResponse;
        boolean removed = claimValueListInResponse.remove(claimValueToRemove);

        if (removed) {
            return new OperationExecutionResult(operation, OperationExecutionResult.Status.SUCCESS,
                    "Claim value removed.");
        } else {
            return new OperationExecutionResult(operation, OperationExecutionResult.Status.FAILURE,
                    "Failed to remove claim value.");
        }
    }

    private OperationExecutionResult removePrimitiveTypeClaim(PerformableOperation operation,
                                                              ClaimPathInfo claimPathInfo,
                                                              IDTokenDTO responseIDTokenDTO) {

        boolean claimRemoved =
                responseIDTokenDTO.getCustomOIDCClaims().remove(claimPathInfo.getClaimName()) != null;

        if (claimRemoved) {
            return new OperationExecutionResult(operation, OperationExecutionResult.Status.SUCCESS,
                    "Claim removed.");
        } else {
            return new OperationExecutionResult(operation, OperationExecutionResult.Status.FAILURE,
                    "Failed to remove claim.");
        }
    }

    private OperationExecutionResult handleReplaceOperation(PerformableOperation operation,
                                                            IDToken requestedIDToken,
                                                            IDTokenDTO responseIDTokenDTO) {

        if (operation.getPath().startsWith(CLAIMS_PATH_PREFIX)) {
            return replaceClaim(operation, requestedIDToken, responseIDTokenDTO);
        }

        return new OperationExecutionResult(operation, OperationExecutionResult.Status.FAILURE,
                "Unsupported path for REPLACE operation: " + operation.getPath());
    }

    private OperationExecutionResult replaceClaim(PerformableOperation operation, IDToken requestIDToken,
                                                  IDTokenDTO responseIDTokenDTO) {


        if (operation.getPath().equals(CLAIMS_PATH_PREFIX + IDToken.ClaimNames.EXPIRES_IN.getName())) {
            return replaceExpiresIn(operation, responseIDTokenDTO);
        } else if (operation.getPath().startsWith(CLAIMS_PATH_PREFIX + IDToken.ClaimNames.AUD.getName())) {
            return replaceAudience(operation, requestIDToken, responseIDTokenDTO);
        } else {
            return replaceOtherClaims(operation, requestIDToken, responseIDTokenDTO);
        }
    }

    private OperationExecutionResult replaceExpiresIn(PerformableOperation operation,
                                                      IDTokenDTO responseIDTokenBuilderDTO) {

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

        responseIDTokenBuilderDTO.setExpiresIn(expiresIn * 1000);
        return new OperationExecutionResult(operation, OperationExecutionResult.Status.SUCCESS,
                "Expiry time updated.");
    }

    private OperationExecutionResult replaceOtherClaims(PerformableOperation operation,
                                                        IDToken requestIDToken,
                                                        IDTokenDTO responseIDTokenDTO) {

        List<String> pathSegments = extractNestedClaimPath(operation.getPath());

        // Nested replace
        if (pathSegments.size() > 1 && !isArrayIndexPath(pathSegments)) {
            return replaceNestedClaim(pathSegments, requestIDToken, responseIDTokenDTO, operation);
        }

        ClaimPathInfo claimPathInfo = parseOperationPath(operation.getPath());
        IDToken.Claim claim = requestIDToken.getClaim(claimPathInfo.getClaimName());

        if (claim == null) {
            return new OperationExecutionResult(operation, OperationExecutionResult.Status.FAILURE,
                    "Claim not found.");
        }

        if (claimPathInfo.getIndex() != -1) {
            return replaceClaimValueAtIndexFromArrayTypeClaim(operation, claimPathInfo, claim, responseIDTokenDTO);
        } else {
            return replacePrimitiveTypeClaim(operation, claimPathInfo, responseIDTokenDTO);
        }
    }

    private OperationExecutionResult replaceNestedClaim(List<String> pathSegments, IDToken requestIDToken,
                                                        IDTokenDTO responseIDTokenDTO,
                                                        PerformableOperation operation) {

        String rootClaimName = pathSegments.get(0);
        List<String> nestedPath = pathSegments.subList(1, pathSegments.size());

        IDToken.Claim rootClaim = requestIDToken.getClaim(rootClaimName);
        if (rootClaim == null || !(rootClaim.getValue() instanceof Map)) {
            return new OperationExecutionResult(operation, OperationExecutionResult.Status.FAILURE,
                    "Root claim is not a complex object.");
        }

        Map<String, Object> rootValue = new HashMap<>((Map<String, Object>) rootClaim.getValue());

        boolean replaced = replaceInNestedMap(rootValue, nestedPath, 0, operation.getValue());
        if (!replaced) {
            return new OperationExecutionResult(operation, OperationExecutionResult.Status.FAILURE,
                    "Nested claim not found.");
        }

        if (rootValue.isEmpty()) {
            responseIDTokenDTO.getCustomOIDCClaims().remove(rootClaimName);
        } else {
            responseIDTokenDTO.getCustomOIDCClaims().put(rootClaimName, rootValue);
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
                                                                                IDToken.Claim claim,
                                                                                IDTokenDTO responseIDTokenDTO) {

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
        Object claimInResponse = responseIDTokenDTO.getCustomOIDCClaims().get(claimPathInfo.getClaimName());
        List<String> claimValueListInResponse = (List<String>) claimInResponse;
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
                                                               IDTokenDTO responseIDTokenDTO) {

        boolean claimExists = responseIDTokenDTO.getCustomOIDCClaims().get(claimPathInfo.getClaimName()) != null;
        if (claimExists) {
            responseIDTokenDTO.getCustomOIDCClaims().put(claimPathInfo.getClaimName(), operation.getValue());
            return new OperationExecutionResult(operation, OperationExecutionResult.Status.SUCCESS,
                    "Claim replaced.");
        } else {
            return new OperationExecutionResult(operation, OperationExecutionResult.Status.FAILURE,
                    "Failed to replace claim.");
        }
    }

    private OperationExecutionResult replaceAudience(PerformableOperation operation,
                                                     IDToken requestIDToken,
                                                     IDTokenDTO responseIDTokenDTO) {

        IDToken.Claim audience = requestIDToken.getClaim(IDToken.ClaimNames.AUD.getName());
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

            List<String> responseAudienceList =
                    responseIDTokenDTO.getAudience();
            responseAudienceList.remove(audienceToReplace);
            responseAudienceList.add(audienceToAdd);
            return new OperationExecutionResult(operation, OperationExecutionResult.Status.SUCCESS,
                    "Audience replaced.");
        }

        return new OperationExecutionResult(operation, OperationExecutionResult.Status.FAILURE,
                "Audience claim not found.");
    }

    private boolean isValidStringOrURI(String input) {

        Matcher matcher = STRING_OR_URI_PATTERN.matcher(input);
        return matcher.matches();
    }

    private boolean isArrayIndexPath(List<String> pathSegments) {

        if (pathSegments.size() != 2) {
            return false;
        }

        String lastSegment = pathSegments.get(1);
        if (LAST_ELEMENT_CHARACTER.equals(lastSegment)) {
            return true;
        }

        try {
            Integer.parseInt(lastSegment);
            return true;
        } catch (NumberFormatException e) {
            return false;
        }
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
}
