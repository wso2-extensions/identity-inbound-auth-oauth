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
package org.wso2.carbon.identity.oidc.dcr.processor;


import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityResponse;
import org.wso2.carbon.identity.oauth.dcr.DCRException;
import org.wso2.carbon.identity.oauth.dcr.context.DCRMessageContext;
import org.wso2.carbon.identity.oauth.dcr.exception.RegistrationException;
import org.wso2.carbon.identity.oauth.dcr.processor.DCRProcessor;
import org.wso2.carbon.identity.oidc.dcr.context.OIDCDCRMessageContext;
import org.wso2.carbon.identity.oidc.dcr.model.OIDCRegistrationRequest;
import org.wso2.carbon.identity.oidc.dcr.util.OIDCDCRConstants;

import java.util.regex.Matcher;

public class OIDCDCRProcessor extends DCRProcessor {

    private static final Log log = LogFactory.getLog(OIDCDCRProcessor.class);

    @Override
    public IdentityResponse.IdentityResponseBuilder process(IdentityRequest identityRequest) throws DCRException {

        if (log.isDebugEnabled()) {
            log.debug("Request processing started by OIDCDCRProcessor.");
        }
        OIDCDCRMessageContext oidcdcrMessageContext = new OIDCDCRMessageContext(identityRequest);
        IdentityResponse.IdentityResponseBuilder identityResponseBuilder = null;
        if (identityRequest instanceof OIDCRegistrationRequest) {
            identityResponseBuilder = registerOAuthApplication(oidcdcrMessageContext);
        } else {
            identityResponseBuilder = super.process(identityRequest);
        }

        return identityResponseBuilder;
    }

    @Override
    protected IdentityResponse.IdentityResponseBuilder registerOAuthApplication(DCRMessageContext dcrMessageContext)
            throws RegistrationException {
        return super.registerOAuthApplication(dcrMessageContext);
    }

    @Override
    public boolean canHandle(IdentityRequest identityRequest) {
        boolean canHandle = false;
        if (identityRequest != null) {
            Matcher registerMatcher =
                    OIDCDCRConstants.OIDC_DCR_ENDPOINT_REGISTER_URL_PATTERN.matcher(identityRequest.getRequestURI());
            if (registerMatcher.matches()) {
                canHandle = true;
            }
        }
        if (log.isDebugEnabled()) {
            log.debug("canHandle " + canHandle + " by OIDCDCRProcessor.");
        }
        return canHandle;
    }


}
