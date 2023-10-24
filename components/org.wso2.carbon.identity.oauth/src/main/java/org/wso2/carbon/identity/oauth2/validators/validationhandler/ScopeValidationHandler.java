/*
 * Copyright (c) 2023, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.oauth2.validators.validationhandler;

import java.util.List;

/**
 * Each scope validation handler for authorized policies should implement this.
 */
public interface ScopeValidationHandler {

    /**
     * Check if the handler can handle the scope validation
     *
     * @param scopeValidationContext ScopeValidationContext.
     * @return boolean
     */
    boolean canHandle(ScopeValidationContext scopeValidationContext);

    /**
     * Validate scopes.
     *
     * @param requestedScopes        Requested scopes.
     * @param appAuthorizedScopes    Authorized scopes.
     * @param scopeValidationContext ScopeValidationContext.
     * @return List of scopes.
     * @throws ScopeValidationHandlerException Error when performing the scope validation.
     */
    List<String> validateScopes(List<String> requestedScopes, List<String> appAuthorizedScopes,
                                ScopeValidationContext scopeValidationContext) throws ScopeValidationHandlerException;

    /**
     * Get policy ID.
     *
     * @return Policy ID.
     */
    String getPolicyID();

    /**
     * Get handler name.
     *
     * @return Handler name.
     */

    String getName();

}
