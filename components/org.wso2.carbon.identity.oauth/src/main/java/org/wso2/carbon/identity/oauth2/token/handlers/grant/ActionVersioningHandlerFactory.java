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

package org.wso2.carbon.identity.oauth2.token.handlers.grant;

import org.wso2.carbon.identity.action.execution.api.model.ActionType;
import org.wso2.carbon.identity.action.execution.api.service.ActionVersioningHandler;

/**
 * Factory class for obtaining the ActionVersioningHandler specific to the SAML grant.
 * This delegates the request to the main ActionVersioningHandlerFactory.
 */
public class ActionVersioningHandlerFactory {

    private static final ActionVersioningHandlerFactory instance = new ActionVersioningHandlerFactory();

    public static ActionVersioningHandlerFactory getInstance() {

        return instance;
    }

    /**
     * Returns an {@link ActionVersioningHandler} instance for the specified action version.
     *
     * @param actionType The type of the action.
     * @param actionVersion The version of the action for which the request builder is required.
     * @return An instance of {@link ActionVersioningHandler} corresponding to the given version.
     */
    public ActionVersioningHandler getVersionTriggerEvaluator(ActionType actionType, String actionVersion) {

        // Delegate to the main OAuth ActionVersioningHandlerFactory to get the correct version handler.
        return ActionVersioningHandlerFactory.getInstance().getVersionTriggerEvaluator(actionType, actionVersion);
    }
}
