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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.fga.services;

import org.wso2.carbon.identity.oauth2.fga.FGAuthorizationException;
import org.wso2.carbon.identity.oauth2.fga.models.AuthzBulkCheckRequest;
import org.wso2.carbon.identity.oauth2.fga.models.AuthzBulkCheckResponse;
import org.wso2.carbon.identity.oauth2.fga.models.AuthzCheckRequest;
import org.wso2.carbon.identity.oauth2.fga.models.AuthzCheckResponse;
import org.wso2.carbon.identity.oauth2.fga.models.ListObjectsRequest;
import org.wso2.carbon.identity.oauth2.fga.models.ListObjectsResponse;

/**
 * Interface for authorization using a FGA connector.
 */
public interface FGAuthorizationInterface {

    AuthzCheckResponse checkAuthorization(AuthzCheckRequest authzCheckRequest) throws FGAuthorizationException;

    AuthzBulkCheckResponse bulkCheckAuthorization
            (AuthzBulkCheckRequest authzBulkCheckRequest) throws FGAuthorizationException;

    ListObjectsResponse lookUpResources(ListObjectsRequest listObjectsRequest) throws FGAuthorizationException;

    ListObjectsResponse lookUpSubjects(ListObjectsRequest listObjectsRequest) throws FGAuthorizationException;
}