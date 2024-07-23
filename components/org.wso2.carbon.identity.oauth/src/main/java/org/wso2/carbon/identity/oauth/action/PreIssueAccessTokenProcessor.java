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

@SuppressWarnings("unchecked")
public class PreIssueAccessTokenProcessor implements ActionExecutionResponseProcessor {

    private static final Log LOG = LogFactory.getLog(PreIssueAccessTokenProcessor.class);

    private static final String OPERATION_ADD = "add";
    private static final String OPERATION_REMOVE = "remove";
    private static final String OPERATION_REPLACE = "replace";
    private static final String SCOPE_PATH_PREFIX = "/accessToken/scopes/";
    private static final String CLAIMS_PATH_PREFIX = "/accessToken/claims/";
    private static final PreIssueAccessTokenProcessor instance = new PreIssueAccessTokenProcessor();
    private static final Pattern NQCHAR_PATTERN = Pattern.compile("^[\\x21\\x23-\\x5B\\x5D-\\x7E]+$");
    private static final Pattern STRING_OR_URI_PATTERN =
            Pattern.compile("^([a-zA-Z][a-zA-Z0-9+.-]*://[^\\s/$.?#].[^\\s]*)|(^[a-zA-Z0-9.-]+$)");

    public static PreIssueAccessTokenProcessor getInstance() {

        return instance;
    }

    @Override
    public ActionExecutionStatus processSuccessResponse(ActionType actionType, Map<String, Object> eventContext,
                                                        Event event,
                                                        ActionInvocationSuccessResponse actionInvocationSuccessResponse)
            throws ActionExecutionResponseProcessorException {

        OAuthTokenReqMessageContext tokenMessageContext =
                (OAuthTokenReqMessageContext) eventContext.get("tokenMessageContext");
        PreIssueAccessTokenEvent preIssueAccessTokenEvent = (PreIssueAccessTokenEvent) event;
        List<PerformableOperation> operationsToPerform = actionInvocationSuccessResponse.getOperations();

        AccessToken requestAccessToken = preIssueAccessTokenEvent.getAccessToken();
        AccessToken.Builder responseAccessTokenBuilder = preIssueAccessTokenEvent.getAccessToken().copy();

        if (operationsToPerform != null) {
            for (PerformableOperation operation : operationsToPerform) {
                switch (operation.getOp()) {
                    case OPERATION_ADD:
                        handleAddOperation(operation, requestAccessToken, responseAccessTokenBuilder);
                        break;
                    case OPERATION_REMOVE:
                        handleRemoveOperation(operation, requestAccessToken, responseAccessTokenBuilder);
                        break;
                    case OPERATION_REPLACE:
                        handleReplaceOperation(operation, requestAccessToken, responseAccessTokenBuilder);
                        break;
                    default:
                        break;
                }
            }
        }

        AccessToken responseAccessToken = responseAccessTokenBuilder.build();
        updateTokenMessageContext(tokenMessageContext, responseAccessToken);

        return new ActionExecutionStatus(ActionExecutionStatus.Status.SUCCESS, eventContext);
    }

    @Override
    public ActionExecutionStatus processErrorResponse(ActionType actionType, Map<String, Object> map, Event event,
                                                      ActionInvocationErrorResponse actionInvocationErrorResponse)
            throws ActionExecutionResponseProcessorException {

        return null;
    }

    private void updateTokenMessageContext(OAuthTokenReqMessageContext tokenMessageContext,
                                           AccessToken responseAccessToken) {

        tokenMessageContext.setScope(responseAccessToken.getScopes().toArray(new String[0]));

        String expires_in_claim_name = CLAIMS_PATH_PREFIX + AccessToken.ClaimNames.EXPIRES_IN.getName();
        responseAccessToken.getClaims().stream()
                .filter(claim -> expires_in_claim_name.equals(claim.getName()))
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

    private void handleAddOperation(PerformableOperation operation, AccessToken requestAccessToken,
                                    AccessToken.Builder responseAccessToken) {

        if (operation.getPath().startsWith(SCOPE_PATH_PREFIX)) {
            List<String> authorizedScopes =
                    responseAccessToken.getScopes() != null ? responseAccessToken.getScopes() : new ArrayList<>();

            int index = validateIndex(operation.getPath(), authorizedScopes.size());
            if (index == -1) {
                return;
            }

            String scopeToAdd = operation.getValue().toString();
            if (validateNQChar(scopeToAdd) && !authorizedScopes.contains(scopeToAdd)) {
                authorizedScopes.add(scopeToAdd);
                LOG.info("Scope added. Scope : " + scopeToAdd);
            } else {
                //todo: add a diagnostic log indicating this is null
                LOG.info("Scope exists or is null: " + scopeToAdd);
            }

            responseAccessToken.scopes(authorizedScopes);
        } else if (operation.getPath().startsWith(CLAIMS_PATH_PREFIX)) {
            addClaim(operation, requestAccessToken, responseAccessToken);
        }
    }

    private void addClaim(PerformableOperation operation, AccessToken requestAccessToken,
                          AccessToken.Builder responseAccessToken) {

        List<AccessToken.Claim> claims = requestAccessToken.getClaims();

        if (claims == null || claims.isEmpty()) {
            // todo: add a diagnostic log indicating there are no claims to replace
            LOG.warn("No claims to replace");
            return;
        }

        if (operation.getPath().startsWith(CLAIMS_PATH_PREFIX + AccessToken.ClaimNames.AUD.getName())) {

            AccessToken.Claim audience = requestAccessToken.getClaim(AccessToken.ClaimNames.AUD.getName());
            if (audience != null && audience.getValue() != null && audience.getValue() instanceof List) {
                List<String> audienceList = (List<String>) audience.getValue();

                int index = validateIndex(operation.getPath(), audienceList.size());
                if (index == -1) {
                    return;
                }

                String audienceToAdd = operation.getValue().toString();
                if (!isValidStringOrURI(audienceToAdd)) {
                    LOG.warn("Audience is invalid: " + audienceToAdd);
                    return;
                }

                AccessToken.Claim responseAudience =
                        responseAccessToken.getClaim(AccessToken.ClaimNames.AUD.getName());
                List<String> responseAudienceList = (List<String>) responseAudience.getValue();
                if (!responseAudienceList.contains(audienceToAdd)) {
                    responseAudienceList.add(audienceToAdd);
                    LOG.info("Audience added: " + audienceToAdd);
                } else {
                    LOG.warn("Audience already exists: " + audienceToAdd);
                }
            }
        } else {

            int index = validateIndex(operation.getPath(), requestAccessToken.getClaims().size());
            if (index == -1) {
                return;
            }

            Object claimToAdd = operation.getValue();

            ObjectMapper objectMapper = new ObjectMapper();
            try {
                AccessToken.Claim claim = objectMapper.convertValue(claimToAdd, AccessToken.Claim.class);
                if (requestAccessToken.getClaim(claim.getName()) != null) {
                    LOG.warn("An access token claim with the same name already exists: " + claim.getName());
                    return;
                }

                Object claimValue = claim.getValue();
                if (!isValidClaimValue(claimValue, true)) {
                    LOG.warn("Claim value is of an invalid type: " + claimValue.getClass().getSimpleName());
                    return;
                }

                responseAccessToken.addClaim(claim.getName(), claimValue);
                LOG.info("Claim added: " + claim.getName() + " with value: " + claimValue);
            } catch (IllegalArgumentException e) {
                LOG.warn("Failed to convert the claim value to a primitive type: " + claimToAdd.getClass().getName(),
                        e);
            }
        }
    }

    private boolean isValidClaimValue(Object value, boolean isList) {

        if (value instanceof String || value instanceof Number || value instanceof Boolean) {
            return true;
        } else if (isList && value instanceof List<?>) {
            List<?> list = (List<?>) value;
            return list.stream().allMatch(item -> item instanceof String);
        }
        return false;
    }

    private void handleRemoveOperation(PerformableOperation operation, AccessToken requestAccessToken,
                                       AccessToken.Builder responseAccessToken) {

        if (operation.getPath().startsWith(SCOPE_PATH_PREFIX)) {

            if (requestAccessToken.getScopes() == null || requestAccessToken.getScopes().isEmpty()) {
                // todo: add a diagnostic log indicating there are no scopes to remove
                LOG.info("No scopes to remove");
                return;
            }

            int index = validateIndex(operation.getPath(), requestAccessToken.getScopes().size());
            if (index == -1) {
                return;
            }

            String scopeToRemove = requestAccessToken.getScopes().get(index);
            boolean removed = responseAccessToken.getScopes().remove(scopeToRemove);
            if (removed) {
                // todo: add a diagnostic log to indicate scope is removed.
                LOG.info("Scope is removed: " + scopeToRemove);
            }

        } else if (operation.getPath().startsWith(CLAIMS_PATH_PREFIX)) {
            removeClaim(operation, requestAccessToken, responseAccessToken);
        }
    }

    private void removeClaim(PerformableOperation operation, AccessToken requestAccessToken,
                             AccessToken.Builder responseAccessToken) {

        List<AccessToken.Claim> claims = requestAccessToken.getClaims();

        if (claims == null || claims.isEmpty()) {
            // todo: add a diagnostic log indicating there are no claims to replace
            LOG.warn("No claims to remove");
            return;
        }

        if (operation.getPath().startsWith(CLAIMS_PATH_PREFIX + AccessToken.ClaimNames.AUD.getName())) {

            AccessToken.Claim audience = requestAccessToken.getClaim(AccessToken.ClaimNames.AUD.getName());
            if (audience != null && audience.getValue() != null && audience.getValue() instanceof List) {
                List<String> audienceList = (List<String>) audience.getValue();

                int index = validateIndex(operation.getPath(), audienceList.size());
                if (index == -1) {
                    return;
                }

                String audienceToRemove = audienceList.get(index);

                AccessToken.Claim responseAudience =
                        responseAccessToken.getClaim(AccessToken.ClaimNames.AUD.getName());
                List<String> responseAudienceList = (List<String>) responseAudience.getValue();
                boolean removed = responseAudienceList.remove(audienceToRemove);
                if (removed) {
                    LOG.info("Audience removed: " + audienceToRemove);
                }
            }
        } else {

            String operationPath = operation.getPath();
            ClaimPathInfo claimPathInfo = parseOperationPath(operationPath);

            if (requestAccessToken.getClaim(claimPathInfo.getClaimName()) != null) {
                if (claimPathInfo.getIndex() != -1) {
                    AccessToken.Claim claim = requestAccessToken.getClaim(claimPathInfo.getClaimName());
                    List<String> claimValueList = (List<String>) claim.getValue();
                    if (claimPathInfo.getIndex() >= 0 && claimPathInfo.getIndex() < claimValueList.size()) {
                        String claimValueToRemove = claimValueList.get(claimPathInfo.getIndex());

                        AccessToken.Claim claimInResponse = responseAccessToken.getClaim(claimPathInfo.getClaimName());
                        List<String> claimValueListInResponse = (List<String>) claimInResponse.getValue();
                        boolean removed = claimValueListInResponse.remove(claimValueToRemove);
                        if (removed) {
                            LOG.info("Claim value from claim removed. Claim: " + claimPathInfo.getClaimName() +
                                    " Claim value: " + claimValueToRemove);
                        }
                    } else {
                        LOG.warn("Index is out of bounds for claim. Claim: " + claimPathInfo.getClaimName() +
                                " Index: " + claimPathInfo.getIndex());
                    }
                } else {
                    boolean claimRemoved = responseAccessToken.getClaims()
                            .removeIf(claim -> claim.getName().equals(claimPathInfo.getClaimName()));
                    if (claimRemoved) {
                        LOG.info("Claim removed: " + claimPathInfo.getClaimName());
                    }
                }
            }
        }
    }

    public ClaimPathInfo parseOperationPath(String operationPath) {

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

    private void handleReplaceOperation(PerformableOperation operation, AccessToken requestAccessToken,
                                        AccessToken.Builder responseAccessToken) {

        if (operation.getPath().startsWith(SCOPE_PATH_PREFIX)) {
            replaceScope(operation, requestAccessToken, responseAccessToken);
        } else if (operation.getPath().startsWith(CLAIMS_PATH_PREFIX)) {
            replaceClaim(operation, requestAccessToken, responseAccessToken);
        }
    }

    private void replaceScope(PerformableOperation operation, AccessToken requestAccessToken,
                              AccessToken.Builder responseAccessToken) {

        List<String> scopes = requestAccessToken.getScopes();
        if (scopes == null || scopes.isEmpty()) {
            LOG.warn("Attempted to replace a scope, but no scopes are available.");
            return;
        }

        int index = validateIndex(operation.getPath(), scopes.size());
        if (index == -1) {
            return;
        }

        String scopeToAdd = operation.getValue().toString();
        if (!validateNQChar(scopeToAdd)) {
            LOG.warn("Scope is invalid: " + scopeToAdd);
            return;
        }

        if (scopes.contains(scopeToAdd)) {
            LOG.warn("Scope already exists: " + scopeToAdd);
            return;
        }

        String scopeToReplace = scopes.get(index);
        responseAccessToken.getScopes().remove(scopeToReplace);
        responseAccessToken.getScopes().add(scopeToAdd);
        LOG.info("Scope replaced: " + scopeToReplace + " with " + scopeToAdd);
    }

    private void replaceClaim(PerformableOperation operation, AccessToken requestAccessToken,
                              AccessToken.Builder responseAccessToken) {

        List<AccessToken.Claim> claims = requestAccessToken.getClaims();

        if (claims == null || claims.isEmpty()) {
            // todo: add a diagnostic log indicating there are no claims to replace
            LOG.warn("No claims to replace");
            return;
        }

        if (operation.getPath().equals(CLAIMS_PATH_PREFIX + AccessToken.ClaimNames.EXPIRES_IN.getName())) {
            long expiresIn;
            try {
                expiresIn = Long.parseLong(operation.getValue().toString());
            } catch (NumberFormatException e) {
                LOG.warn("Invalid expiry time format: " + operation.getValue().toString(), e);
                return;
            }

            if (expiresIn <= 0) {
                LOG.warn("Invalid expiry time: must be positive, but was " + expiresIn);
                return;
            }

            responseAccessToken.getClaims().removeIf(
                    claim -> claim.getName().equals(CLAIMS_PATH_PREFIX + AccessToken.ClaimNames.EXPIRES_IN.getName()));
            responseAccessToken.addClaim(CLAIMS_PATH_PREFIX + AccessToken.ClaimNames.EXPIRES_IN.getName(), expiresIn);
            LOG.info("Expiry time claim replaced with: " + expiresIn);
        } else if (operation.getPath().startsWith(CLAIMS_PATH_PREFIX + AccessToken.ClaimNames.AUD.getName())) {

            AccessToken.Claim audience = requestAccessToken.getClaim(AccessToken.ClaimNames.AUD.getName());
            if (audience != null && audience.getValue() != null && audience.getValue() instanceof List) {
                List<String> audienceList = (List<String>) audience.getValue();

                int index = validateIndex(operation.getPath(), audienceList.size());
                if (index == -1) {
                    return;
                }

                String audienceToAdd = operation.getValue().toString();
                if (!isValidStringOrURI(audienceToAdd)) {
                    LOG.warn("Audience is invalid: " + audienceToAdd);
                    return;
                }

                if (audienceList.contains(audienceToAdd)) {
                    LOG.warn("Audience already exists: " + audienceToAdd);
                    return;
                }

                String audienceToReplace = audienceList.get(index);

                AccessToken.Claim responseAudience =
                        responseAccessToken.getClaim(AccessToken.ClaimNames.AUD.getName());
                List<String> responseAudienceList = (List<String>) responseAudience.getValue();
                responseAudienceList.remove(audienceToReplace);
                responseAudienceList.add(audienceToAdd);

                LOG.info("Audience replaced: " + audienceToReplace + " with " + audienceToAdd);
            }
        } else {
            String operationPath = operation.getPath();
            ClaimPathInfo claimPathInfo = parseOperationPath(operationPath);

            if (requestAccessToken.getClaim(claimPathInfo.getClaimName()) != null) {
                if (claimPathInfo.getIndex() != -1) {
                    AccessToken.Claim claim = requestAccessToken.getClaim(claimPathInfo.getClaimName());
                    List<String> claimValueList = (List<String>) claim.getValue();
                    if (claimPathInfo.getIndex() >= 0 && claimPathInfo.getIndex() < claimValueList.size()) {
                        String claimToReplace = claimValueList.get(claimPathInfo.getIndex());

                        Object claimValue = operation.getValue();
                        if (!isValidClaimValue(claimValue, false)) {
                            LOG.warn("Claim value is of an invalid type: " + claimValue.getClass().getSimpleName());
                            return;
                        }

                        AccessToken.Claim claimInResponse = responseAccessToken.getClaim(claimPathInfo.getClaimName());
                        List<String> claimValueListInResponse = (List<String>) claimInResponse.getValue();

                        if (claimValueListInResponse.contains(claimValue.toString())) {
                            LOG.warn("Claim value already exists: " + claimValue);
                            return;
                        }

                        claimValueListInResponse.remove(claimToReplace);
                        claimValueListInResponse.add(claimValue.toString());
                        LOG.info("Claim value from claim replaced. Claim: " + claimPathInfo.getClaimName() +
                                " Replaced: " + claimToReplace + " with: " + claimValue);
                    } else {
                        LOG.warn("Index is out of bounds for claim. Claim: " + claimPathInfo.getClaimName() +
                                " Index: " + claimPathInfo.getIndex());
                    }
                } else {
                    boolean claimRemoved = responseAccessToken.getClaims()
                            .removeIf(claim -> claim.getName().equals(claimPathInfo.getClaimName()));
                    if (claimRemoved) {
                        responseAccessToken.addClaim(claimPathInfo.getClaimName(),
                                operation.getValue());
                        LOG.info("Claim removed: " + claimPathInfo.getClaimName());
                    }
                }
            }
        }
    }

    private int validateIndex(String operationPath, int listSize) {

        String indexPart = operationPath.substring(operationPath.lastIndexOf('/') + 1);
        if ("-".equals(indexPart)) {
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
