/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * you may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.oauth.dcr.handler;

import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityResponse;
import org.wso2.carbon.identity.oauth.dcr.DCRException;
import org.wso2.carbon.identity.oauth.dcr.context.DCRMessageContext;
import org.wso2.carbon.identity.oauth.dcr.model.UnregistrationRequest;
import org.wso2.carbon.identity.oauth.dcr.model.UnregistrationResponse;
import org.wso2.carbon.identity.oauth.dcr.service.DCRManagementService;

public class UnRegistrationHandler extends AbstractDCRHandler {

    @Override
    public IdentityResponse.IdentityResponseBuilder handle(DCRMessageContext dcrMessageContext)
        throws DCRException {

        UnregistrationRequest unregistrationRequest = (UnregistrationRequest) dcrMessageContext
            .getIdentityRequest();

        UnregistrationResponse.DCUnregisterResponseBuilder unregisterResponseBuilder =
            new UnregistrationResponse.DCUnregisterResponseBuilder();

        boolean isUnRegistered = DCRManagementService.getInstance()
            .unregisterOAuthApplication(unregistrationRequest.getUserId(), unregistrationRequest
                .getConsumerKey());

        unregisterResponseBuilder.setIsUnregistered(isUnRegistered);

        return unregisterResponseBuilder;
    }
}