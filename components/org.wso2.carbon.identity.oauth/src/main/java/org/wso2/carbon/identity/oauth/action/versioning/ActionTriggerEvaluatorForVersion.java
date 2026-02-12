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
     * Determines whether the action can be triggered based on the flow context for the action version.
     * For V1, the action should not be triggered for grant flows that are not supported in this version.
     *
     * @param actionType The type of the action being evaluated.
     * @param action The action being evaluated.
     * @param flowContext The context of the flow in which the action is being evaluated.
     * @return true if the action can be triggered, false otherwise.
     * @throws ActionExecutionException if there is an error during evaluation.
     */
    public boolean isTriggerableForActionV2SupportedGrants(ActionType actionType, Action action,
                                                           FlowContext flowContext) throws ActionExecutionException {

        OAuthTokenReqMessageContext tokenMessageContext =
                flowContext.getValue("tokenMessageContext", OAuthTokenReqMessageContext.class);

        String grantType = tokenMessageContext.getOauth2AccessTokenReqDTO().getGrantType();

        if (OAuthConstants.GrantTypes.TOKEN_EXCHANGE.equals(grantType)
                || OAuthConstants.GrantTypes.DEVICE_CODE_URN.equals(grantType)
                || OAuthConstants.GrantTypes.JWT_BEARER.equals(grantType)
                || OAuthConstants.GrantTypes.SAML20_BEARER.equals(grantType)) {
            return false;
        }

        return true;
    }
}
