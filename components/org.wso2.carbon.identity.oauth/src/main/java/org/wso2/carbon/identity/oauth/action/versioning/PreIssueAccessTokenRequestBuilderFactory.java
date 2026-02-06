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

package org.wso2.carbon.identity.oauth.action.versioning;

import org.wso2.carbon.identity.action.execution.api.exception.ActionExecutionRequestBuilderException;
import org.wso2.carbon.identity.action.execution.api.service.ActionExecutionRequestBuilder;
import org.wso2.carbon.identity.oauth.action.constant.PreIssueAccessTokenActionConstants;
import org.wso2.carbon.identity.oauth.action.versioning.v1.PreIssueAccessTokenRequestBuilderV1;

/**
 * Factory class for getting the PreIssueAccessRequestBuilder by Action version.
 */
public class PreIssueAccessTokenRequestBuilderFactory {

    private static final PreIssueAccessTokenRequestBuilderFactory instance =
            new PreIssueAccessTokenRequestBuilderFactory();

    public static PreIssueAccessTokenRequestBuilderFactory getInstance() {

        return instance;
    }

    public ActionExecutionRequestBuilder getActionExecutionRequestBuilder(String actionVersion)
            throws ActionExecutionRequestBuilderException {

        switch (actionVersion) {
            case PreIssueAccessTokenActionConstants.ACTION_VERSION_V1:
                return new PreIssueAccessTokenRequestBuilderV1();
            default:
                throw new ActionExecutionRequestBuilderException(
                        "Unsupported pre-issue-access token action version: " + actionVersion);
        }
    }
}
