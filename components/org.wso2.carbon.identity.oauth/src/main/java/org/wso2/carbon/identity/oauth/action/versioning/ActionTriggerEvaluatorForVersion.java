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

package org.wso2.carbon.identity.oauth.action.versioning;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.action.execution.api.exception.ActionExecutionException;
import org.wso2.carbon.identity.action.execution.api.model.ActionType;
import org.wso2.carbon.identity.action.execution.api.model.FlowContext;
import org.wso2.carbon.identity.action.management.api.model.Action;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;

/**
 * Default implementation of the ActionVersioningHandler for PRE_ISSUE_ACCESS_TOKEN (V1 behavior).
 * This class determines whether the action can be triggered based on the flow context for the action version.
 */
public class ActionTriggerEvaluatorForVersion {

    private static final ActionTriggerEvaluatorForVersion instance = new ActionTriggerEvaluatorForVersion();

    private static final Log LOG = LogFactory.getLog(ActionTriggerEvaluatorForVersion.class);

    public static ActionTriggerEvaluatorForVersion getInstance() {

        return instance;
    }

    /**
     * Evaluate whether action can be triggered based on flow context for the given action version.
     *
     * @param actionType  Action type.
     * @param action      Action.
     * @param flowContext Flow context.
     * @return True if action can be triggered based on the flow context.
     */
    public boolean isTriggerableForTokenExchangeGrant(ActionType actionType, Action action, FlowContext flowContext)
            throws ActionExecutionException {

        OAuthTokenReqMessageContext tokenMessageContext =
                flowContext.getValue("tokenMessageContext", OAuthTokenReqMessageContext.class);
        if (OAuthConstants.GrantTypes.TOKEN_EXCHANGE.equals(
                tokenMessageContext.getOauth2AccessTokenReqDTO().getGrantType())) {
            return false;
        }
        return true;
    }
}
