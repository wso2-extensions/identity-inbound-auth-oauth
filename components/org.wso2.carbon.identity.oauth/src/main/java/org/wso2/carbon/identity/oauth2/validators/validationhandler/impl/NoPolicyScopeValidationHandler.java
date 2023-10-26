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

package org.wso2.carbon.identity.oauth2.validators.validationhandler.impl;

import org.wso2.carbon.identity.oauth2.validators.validationhandler.ScopeValidationContext;
import org.wso2.carbon.identity.oauth2.validators.validationhandler.ScopeValidationHandler;
import org.wso2.carbon.identity.oauth2.validators.validationhandler.ScopeValidationHandlerException;

import java.util.List;
import java.util.stream.Collectors;

/**
 * No policy scope validation handler handle authorized no policy scopes.
 */
public class NoPolicyScopeValidationHandler implements ScopeValidationHandler {

    @Override
    public boolean canHandle(ScopeValidationContext scopeValidationContext) {

        return getPolicyID().equals(scopeValidationContext.getPolicyId());
    }

    @Override
    public List<String> validateScopes(List<String> requestedScopes, List<String> appAuthorizedScopes,
                                       ScopeValidationContext scopeValidationContext)
            throws ScopeValidationHandlerException {

        return requestedScopes.stream().filter(appAuthorizedScopes::contains).collect(Collectors.toList());
    }

    @Override
    public String getPolicyID() {

        return "NO POLICY";
    }

    @Override
    public String getName() {

        return "NoPolicyScopeValidationHandler";
    }
}
