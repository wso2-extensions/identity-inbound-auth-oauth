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


import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityResponse;
import org.wso2.carbon.identity.oauth.dcr.DCRException;
import org.wso2.carbon.identity.oauth.dcr.context.DCRMessageContext;
import org.wso2.carbon.identity.oauth.dcr.model.RegistrationRequest;
import org.wso2.carbon.identity.oauth.dcr.model.RegistrationRequestProfile;
import org.wso2.carbon.identity.oauth.dcr.model.RegistrationResponse;
import org.wso2.carbon.identity.oauth.dcr.model.RegistrationResponseProfile;
import org.wso2.carbon.identity.oauth.dcr.service.DCRManagementService;

public class RegistrationHandler extends AbstractDCRHandler {
    private static final Log log = LogFactory.getLog(RegistrationHandler.class);

    @Override
    public IdentityResponse.IdentityResponseBuilder handle(DCRMessageContext dcrMessageContext) throws DCRException {
        if (log.isDebugEnabled()) {
            log.debug("Request processing started by RegistrationRequestProcessor.");
        }
        RegistrationResponse.DCRRegisterResponseBuilder dcrRegisterResponseBuilder = null;

        RegistrationRequest registerRequest = (RegistrationRequest) dcrMessageContext.getIdentityRequest();
        RegistrationRequestProfile registrationRequestProfile = registerRequest.getRegistrationRequestProfile();
        registrationRequestProfile.setTenantDomain(registerRequest.getTenantDomain());

        RegistrationResponseProfile registrationResponseProfile =
                DCRManagementService.getInstance().registerOAuthApplication(registrationRequestProfile);

        dcrRegisterResponseBuilder = new RegistrationResponse.DCRRegisterResponseBuilder();
        dcrRegisterResponseBuilder.setRegistrationResponseProfile(registrationResponseProfile);


        return dcrRegisterResponseBuilder;
    }
}
