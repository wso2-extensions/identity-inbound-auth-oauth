/*
 *  Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
 *
 *  WSO2 LLC. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */

package org.wso2.carbon.identity.oauth2.finegrainedauthz;

import org.wso2.carbon.identity.authorization.framework.exception.AccessEvaluationException;
import org.wso2.carbon.identity.authorization.framework.model.AccessEvaluationRequest;
import org.wso2.carbon.identity.authorization.framework.model.AccessEvaluationResponse;
import org.wso2.carbon.identity.authorization.framework.model.BulkAccessEvaluationRequest;
import org.wso2.carbon.identity.authorization.framework.model.BulkAccessEvaluationResponse;
import org.wso2.carbon.identity.authorization.framework.model.SearchActionsRequest;
import org.wso2.carbon.identity.authorization.framework.model.SearchActionsResponse;
import org.wso2.carbon.identity.authorization.framework.model.SearchResourcesRequest;
import org.wso2.carbon.identity.authorization.framework.model.SearchResourcesResponse;
import org.wso2.carbon.identity.authorization.framework.model.SearchSubjectsRequest;
import org.wso2.carbon.identity.authorization.framework.model.SearchSubjectsResponse;
import org.wso2.carbon.identity.authorization.framework.service.AccessEvaluationService;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth2.OAuth2Constants;

import java.util.List;

/**
 * This class is used to perform the fine-grained API authorization.
 */
public class FineGrainedApiAccessEvaluationService implements AccessEvaluationService {


    @Override
    public String getEngine() {
        return "";
    }

    @Override
    public AccessEvaluationResponse evaluate(AccessEvaluationRequest accessEvaluationRequest)
            throws AccessEvaluationException {

        FineGrainedApiScope fineGrainedApiScope = new FineGrainedApiScope();
        List<String> authorizedScopes = (List<String>) IdentityUtil.threadLocalProperties.get().get(
                OAuth2Constants.AUTHORIZED_SCOPES);
        String requiredScope = fineGrainedApiScope.resolve(accessEvaluationRequest.getActionObject().getAction());
        if (authorizedScopes != null && authorizedScopes.contains(requiredScope)) {
            return new AccessEvaluationResponse(
                    true);
        }

        return new AccessEvaluationResponse(false);
    }

    @Override
    public BulkAccessEvaluationResponse bulkEvaluate(BulkAccessEvaluationRequest bulkAccessEvaluationRequest)
            throws AccessEvaluationException {
        return null;
    }

    @Override
    public SearchResourcesResponse searchResources(SearchResourcesRequest searchResourcesRequest)
            throws AccessEvaluationException {
        return null;
    }

    @Override
    public SearchSubjectsResponse searchSubjects(SearchSubjectsRequest searchSubjectsRequest)
            throws AccessEvaluationException {
        return null;
    }

    @Override
    public SearchActionsResponse searchActions(SearchActionsRequest searchActionsRequest)
            throws AccessEvaluationException {
        return null;
    }
}
