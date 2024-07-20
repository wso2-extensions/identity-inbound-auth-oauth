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

package org.wso2.carbon.identity.actions.util;

import org.wso2.carbon.identity.actions.model.AllowedOperation;
import org.wso2.carbon.identity.actions.model.PerformableOperation;

public class OperationComparator {

    public static boolean compare(AllowedOperation allowedOp, PerformableOperation performableOp) {

        if (!allowedOp.getOp().equals(performableOp.getOp())) {
            return false;
        }

        String performableOperationBasePath = performableOp.getPath().contains("/")
                ? performableOp.getPath().substring(0, performableOp.getPath().lastIndexOf('/') + 1)
                : "";

        for (String allowedPath : allowedOp.getPaths()) {
            if (performableOp.getPath().equals(allowedPath) ||
                    performableOperationBasePath.equals(allowedPath)) {
                return true;
            }
        }

        return false;
    }
}
