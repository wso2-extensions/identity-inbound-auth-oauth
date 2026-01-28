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

import org.wso2.carbon.identity.action.execution.api.exception.ActionExecutionRequestBuilderException;
import org.wso2.carbon.identity.action.execution.api.model.ActionExecutionRequest;
import org.wso2.carbon.identity.action.execution.api.model.ActionExecutionRequestContext;
import org.wso2.carbon.identity.action.execution.api.model.ActionType;
import org.wso2.carbon.identity.action.execution.api.model.FlowContext;
import org.wso2.carbon.identity.action.execution.api.service.ActionExecutionRequestBuilder;
import org.wso2.carbon.identity.oauth.action.versioning.PreIssueAccessTokenRequestBuilderFactory;

/**
 * This class is responsible for building the action execution request for the pre issue access token action.
 */
public class PreIssueAccessTokenRequestBuilder implements ActionExecutionRequestBuilder {

    public static final String ACCESS_TOKEN_CLAIMS_PATH_PREFIX = "/accessToken/claims/";
    public static final String REFRESH_TOKEN_CLAIMS_PATH_PREFIX = "/refreshToken/claims/";
    public static final String SCOPES_PATH_PREFIX = "/accessToken/scopes/";

    @Override
    public ActionType getSupportedActionType() {

        return ActionType.PRE_ISSUE_ACCESS_TOKEN;
    }

    @Override
    public ActionExecutionRequest buildActionExecutionRequest(FlowContext flowContext,
                                                              ActionExecutionRequestContext actionExecutionContext)
            throws ActionExecutionRequestBuilderException {

        ActionExecutionRequestBuilder actionRequestBuilder = PreIssueAccessTokenRequestBuilderFactory.getInstance()
                .getActionExecutionRequestBuilder(actionExecutionContext.getAction().getActionVersion());

        return actionRequestBuilder.buildActionExecutionRequest(flowContext, actionExecutionContext);
    }
}
