/*
 * Copyright (c) 2024, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.oauth.action;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.action.execution.ActionExecutionResponseProcessor;
import org.wso2.carbon.identity.action.execution.exception.ActionExecutionResponseProcessorException;
import org.wso2.carbon.identity.action.execution.model.ActionExecutionStatus;
import org.wso2.carbon.identity.action.execution.model.ActionInvocationErrorResponse;
import org.wso2.carbon.identity.action.execution.model.ActionInvocationSuccessResponse;
import org.wso2.carbon.identity.action.execution.model.ActionType;
import org.wso2.carbon.identity.action.execution.model.Event;
import org.wso2.carbon.identity.action.execution.model.PerformableOperation;
import org.wso2.carbon.identity.oauth.action.model.AccessToken;
import org.wso2.carbon.identity.oauth.action.model.ClaimPathInfo;
import org.wso2.carbon.identity.oauth.action.model.OperationExecutionResult;
import org.wso2.carbon.identity.oauth.action.model.PreIssueAccessTokenEvent;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * This class is responsible for processing the response received from the action execution
 * of the pre issue access token.
 */
public class PreIssueAccessTokenResponseProcessor implements ActionExecutionResponseProcessor {

    private static final Log LOG = LogFactory.getLog(PreIssueAccessTokenResponseProcessor.class);
    private static final String SCOPE_PATH_PREFIX = "/accessToken/scopes/";
    private static final String CLAIMS_PATH_PREFIX = "/accessToken/claims/";
    private static final Pattern NQCHAR_PATTERN = Pattern.compile("^[\\x21\\x23-\\x5B\\x5D-\\x7E]+$");
    private static final Pattern STRING_OR_URI_PATTERN =
            Pattern.compile("^([a-zA-Z][a-zA-Z0-9+.-]*://[^\\s/$.?#].\\S*)|(^[a-zA-Z0-9.-]+$)");
    private static final String LAST_ELEMENT_CHARACTER = "-";
    private static final char PATH_SEPARATOR = '/';

    @Override
    public ActionType getSupportedActionType() {

        return ActionType.PRE_ISSUE_ACCESS_TOKEN;
    }

    @Override
    public ActionExecutionStatus processSuccessResponse(Map<String, Object> eventContext, Event event,
                                                        ActionInvocationSuccessResponse actionInvocationSuccessResponse)
            throws ActionExecutionResponseProcessorException {

        OAuthTokenReqMessageContext tokenMessageContext =
                (OAuthTokenReqMessageContext) eventContext.get("tokenMessageContext");
        PreIssueAccessTokenEvent preIssueAccessTokenEvent = (PreIssueAccessTokenEvent) event;
        List<PerformableOperation> operationsToPerform = actionInvocationSuccessResponse.getOperations();

        AccessToken requestAccessToken = preIssueAccessTokenEvent.getAccessToken();
        AccessToken.Builder responseAccessTokenBuilder = preIssueAccessTokenEvent.getAccessToken().copy();
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
                        break;
                    default:
                        break;
                }
            }
        }

        logOperationExecutionResults(getSupportedActionType(), operationExecutionResultList);

        AccessToken responseAccessToken = responseAccessTokenBuilder.build();
        updateTokenMessageContext(tokenMessageContext, responseAccessToken);

        return new ActionExecutionStatus(ActionExecutionStatus.Status.SUCCESS, eventContext);
    }

    private void logOperationExecutionResults(ActionType actionType,
                                              List<OperationExecutionResult> operationExecutionResultList) {

        //todo: need to add to diagnostic logs
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
    public ActionExecutionStatus processErrorResponse(Map<String, Object> map, Event event,
                                                      ActionInvocationErrorResponse actionInvocationErrorResponse)
            throws ActionExecutionResponseProcessorException {

        //todo: need to implement to process the error so that if a processable error is received
        // it is communicated to the client.
        // we will look into this as we go along with other extension types validating the way to model this.
        return null;
    }

    private void updateTokenMessageContext(OAuthTokenReqMessageContext tokenMessageContext,
                                           AccessToken responseAccessToken) {

        tokenMessageContext.setScope(responseAccessToken.getScopes().toArray(new String[0]));

        String expiresInClaimName = CLAIMS_PATH_PREFIX + AccessToken.ClaimNames.EXPIRES_IN.getName();
        responseAccessToken.getClaims().stream()
                .filter(claim -> expiresInClaimName.equals(claim.getName()))
                .findFirst()
                .map(claim -> Long.parseLong(claim.getValue().toString()) * 1000)
                .ifPresent(tokenMessageContext::setValidityPeriod);

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
        } else if (operation.getPath().startsWith(CLAIMS_PATH_PREFIX)) {
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

        if (operation.getPath().startsWith(CLAIMS_PATH_PREFIX + AccessToken.ClaimNames.AUD.getName())) {
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
            if (requestAccessToken.getClaim(claim.getName()) != null) {
                return new OperationExecutionResult(operation, OperationExecutionResult.Status.FAILURE,
                        "An access token claim already exists.");
            }

            Object claimValue = claim.getValue();
            if (isValidPrimitiveValue(claimValue) || isValidListValue(claimValue)) {
                responseAccessToken.addClaim(claim.getName(), claimValue);
                return new OperationExecutionResult(operation, OperationExecutionResult.Status.SUCCESS, "Claim added.");

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
        } else if (operation.getPath().startsWith(CLAIMS_PATH_PREFIX)) {
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

        if (operation.getPath().startsWith(CLAIMS_PATH_PREFIX + AccessToken.ClaimNames.AUD.getName())) {
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

        ClaimPathInfo claimPathInfo = parseOperationPath(operation.getPath());
        AccessToken.Claim claim = requestAccessToken.getClaim(claimPathInfo.getClaimName());
        if (claim == null) {
            return new OperationExecutionResult(operation, OperationExecutionResult.Status.FAILURE, "Claim not found.");
        }

        if (claimPathInfo.getIndex() != -1) {
            return removeClaimValueAtIndexFromArrayTypeClaim(operation, claimPathInfo, claim,
                    responseAccessToken);
        } else {
            return removePrimitiveTypeClaim(operation, claimPathInfo, responseAccessToken);
        }
    }

    private OperationExecutionResult removeClaimValueAtIndexFromArrayTypeClaim(PerformableOperation operation,
                                                                               ClaimPathInfo claimPathInfo,
                                                                               AccessToken.Claim claim,
                                                                               AccessToken.Builder
                                                                                       responseAccessToken) {

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

        AccessToken.Claim claimInResponse =
                responseAccessToken.getClaim(claimPathInfo.getClaimName());
        List<String> claimValueListInResponse = (List<String>) claimInResponse.getValue();
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

    private OperationExecutionResult handleReplaceOperation(PerformableOperation operation,
                                                            AccessToken requestAccessToken,
                                                            AccessToken.Builder responseAccessToken) {

        if (operation.getPath().startsWith(SCOPE_PATH_PREFIX)) {
            return replaceScope(operation, requestAccessToken, responseAccessToken);
        } else if (operation.getPath().startsWith(CLAIMS_PATH_PREFIX)) {
            return replaceClaim(operation, requestAccessToken, responseAccessToken);
        }
        return new OperationExecutionResult(operation, OperationExecutionResult.Status.FAILURE,
                "Unknown path.");
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

    private OperationExecutionResult replaceClaim(PerformableOperation operation, AccessToken requestAccessToken,
                                                  AccessToken.Builder responseAccessToken) {

        List<AccessToken.Claim> claims = requestAccessToken.getClaims();

        if (claims == null || claims.isEmpty()) {
            return new OperationExecutionResult(operation, OperationExecutionResult.Status.FAILURE,
                    "No claims to replace.");
        }

        if (operation.getPath().equals(CLAIMS_PATH_PREFIX + AccessToken.ClaimNames.EXPIRES_IN.getName())) {
            return replaceExpiresIn(operation, responseAccessToken);
        } else if (operation.getPath().startsWith(CLAIMS_PATH_PREFIX + AccessToken.ClaimNames.AUD.getName())) {
            return replaceAudience(operation, requestAccessToken, responseAccessToken);
        } else {
            return replaceOtherClaims(operation, requestAccessToken, responseAccessToken);
        }
    }

    private OperationExecutionResult replaceExpiresIn(PerformableOperation operation,
                                                      AccessToken.Builder responseAccessToken) {

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

        responseAccessToken.getClaims().removeIf(
                claim -> claim.getName()
                        .equals(CLAIMS_PATH_PREFIX + AccessToken.ClaimNames.EXPIRES_IN.getName()));
        responseAccessToken.addClaim(CLAIMS_PATH_PREFIX + AccessToken.ClaimNames.EXPIRES_IN.getName(),
                expiresIn);
        return new OperationExecutionResult(operation, OperationExecutionResult.Status.SUCCESS,
                "Expiry time updated.");
    }

    private OperationExecutionResult replaceOtherClaims(PerformableOperation operation, AccessToken requestAccessToken,
                                                        AccessToken.Builder responseAccessToken) {

        ClaimPathInfo claimPathInfo = parseOperationPath(operation.getPath());
        AccessToken.Claim claim = requestAccessToken.getClaim(claimPathInfo.getClaimName());

        if (claim == null) {
            return new OperationExecutionResult(operation, OperationExecutionResult.Status.FAILURE,
                    "Claim not found.");
        }

        if (claimPathInfo.getIndex() != -1) {
            return replaceClaimValueAtIndexFromArrayTypeClaim(operation, claimPathInfo, claim, responseAccessToken);
        } else {
            return replacePrimitiveTypeClaim(operation, claimPathInfo, responseAccessToken);
        }
    }

    private OperationExecutionResult replaceClaimValueAtIndexFromArrayTypeClaim(PerformableOperation operation,
                                                                                ClaimPathInfo claimPathInfo,
                                                                                AccessToken.Claim claim,
                                                                                AccessToken.Builder
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
                                                               AccessToken.Builder responseAccessToken) {

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
