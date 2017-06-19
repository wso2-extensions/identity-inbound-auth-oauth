/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityResponse.IdentityResponseBuilder;
import org.wso2.carbon.identity.oauth.dcr.DCRException;
import org.wso2.carbon.identity.oauth.dcr.context.DCRMessageContext;
import org.wso2.carbon.identity.oauth.dcr.model.RegistrationResponse;
import org.wso2.carbon.identity.oauth.dcr.model.RegistrationResponse.DCRRegisterResponseBuilder;
import org.wso2.carbon.identity.oauth.dcr.model.RegistrationResponseProfile;
import org.wso2.carbon.identity.oauth.dcr.model.UpdateRequest;
import org.wso2.carbon.identity.oauth.dcr.model.UpdateRequestProfile;
import org.wso2.carbon.identity.oauth.dcr.service.DCRManagementService;

/**
 * UpdateHandler handles the request for DCRM update.
 */
public class UpdateHandler extends AbstractDCRHandler{

    @Override
    public IdentityResponseBuilder handle(DCRMessageContext dcrMessageContext) throws DCRException {

        RegistrationResponse.DCRRegisterResponseBuilder updateResponseBuilder;

        UpdateRequest updateRequest = (UpdateRequest) dcrMessageContext.getIdentityRequest();

        UpdateRequestProfile updateRequestProfile = updateRequest.getUpdateRequestProfile();

        updateRequestProfile.setTenantDomain(updateRequest.getTenantDomain());

        RegistrationResponseProfile registrationResponseProfile = DCRManagementService.getInstance()
            .updateOAuthApplication(updateRequestProfile);

        updateResponseBuilder = new RegistrationResponse.DCRRegisterResponseBuilder();

        updateResponseBuilder.setRegistrationResponseProfile(registrationResponseProfile);

        return updateResponseBuilder;
    }
}
