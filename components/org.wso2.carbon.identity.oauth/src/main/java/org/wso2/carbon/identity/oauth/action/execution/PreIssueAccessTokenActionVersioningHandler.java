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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.action.execution;

import org.wso2.carbon.identity.action.execution.api.exception.ActionExecutionException;
import org.wso2.carbon.identity.action.execution.api.model.ActionExecutionRequestContext;
import org.wso2.carbon.identity.action.execution.api.model.ActionType;
import org.wso2.carbon.identity.action.execution.api.model.FlowContext;
import org.wso2.carbon.identity.action.execution.api.service.impl.DefaultActionVersioningHandler;
import org.wso2.carbon.identity.action.management.api.model.Action;
import org.wso2.carbon.identity.oauth.action.versioning.ActionTriggerEvaluatorFactory;
import org.wso2.carbon.identity.oauth.action.versioning.ActionTriggerEvaluatorForVersion;

/**
 * Implementation of the Version handler for pre issue access token action.
 */
public class PreIssueAccessTokenActionVersioningHandler extends DefaultActionVersioningHandler {

    ActionTriggerEvaluatorFactory factory = ActionTriggerEvaluatorFactory.getInstance();

    @Override
    public ActionType getSupportedActionType() {

        return ActionType.PRE_ISSUE_ACCESS_TOKEN;
    }

    @Override
    public boolean canExecute(ActionExecutionRequestContext actionExecutionRequestContext, FlowContext flowContext)
            throws ActionExecutionException {

        Action action = actionExecutionRequestContext.getAction();
        ActionTriggerEvaluatorForVersion versionTriggerEvaluator = factory.getVersionTriggerEvaluator(action);

        if (!versionTriggerEvaluator.isTriggerableForActionV2SupportedGrants(
                actionExecutionRequestContext.getActionType(), action, flowContext)) {
            return false;
        }

        return true;
    }
}
