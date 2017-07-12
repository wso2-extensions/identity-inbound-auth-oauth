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

package org.wso2.carbon.identity.oidc.dcr.factory;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkClientException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkRuntimeException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.oauth.dcr.factory.RegistrationRequestFactory;
import org.wso2.carbon.identity.oidc.dcr.model.OIDCRegistrationRequest;
import org.wso2.carbon.identity.oidc.dcr.model.OIDCRegistrationRequestProfile;
import org.wso2.carbon.identity.oidc.dcr.util.OIDCDCRConstants;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.HttpMethod;
import java.util.regex.Matcher;

/**
 * OIDCRegistrationRequestFactory build the request for DCR Registry Request.
 */
public class OIDCRegistrationRequestFactory extends RegistrationRequestFactory {

    private static Log log = LogFactory.getLog(OIDCRegistrationRequestFactory.class);

    @Override
    public boolean canHandle(HttpServletRequest request, HttpServletResponse response) throws
            FrameworkRuntimeException {

        boolean canHandle = false;
        if (request != null) {
            Matcher matcher = OIDCDCRConstants.OIDC_DCR_ENDPOINT_REGISTER_URL_PATTERN.matcher(request.getRequestURI());
            if (matcher.matches() && HttpMethod.POST.equals(request.getMethod())) {
                canHandle = true;
            }
        }
        if (log.isDebugEnabled()) {
            log.debug("canHandle " + canHandle + " by OIDCRegistrationRequestFactory.");
        }
        return canHandle;
    }


    @Override
    public OIDCRegistrationRequest.OIDCRegistrationRequestBuilder create(HttpServletRequest request,
                                                                         HttpServletResponse response)
            throws FrameworkClientException {

        if (log.isDebugEnabled()) {
            log.debug("create RegistrationRequest.RegistrationRequestBuilder by OIDCRegistrationRequestFactory.");
        }
        OIDCRegistrationRequest.OIDCRegistrationRequestBuilder registerRequestBuilder = new
                OIDCRegistrationRequest.OIDCRegistrationRequestBuilder(request, response);


        create(registerRequestBuilder, request, response);

        return registerRequestBuilder;

    }

    @Override
    public void create(IdentityRequest.IdentityRequestBuilder builder, HttpServletRequest request,
                       HttpServletResponse response) throws FrameworkClientException {

        OIDCRegistrationRequest.OIDCRegistrationRequestBuilder registerRequestBuilder = null;
        if (builder instanceof OIDCRegistrationRequest.OIDCRegistrationRequestBuilder) {
            registerRequestBuilder =
                    (OIDCRegistrationRequest.OIDCRegistrationRequestBuilder) builder;
            OIDCRegistrationRequestProfile oidcRegistrationRequestProfile = new OIDCRegistrationRequestProfile();
            registerRequestBuilder.setRegistrationRequestProfile(oidcRegistrationRequestProfile);

            super.create(registerRequestBuilder, request, response);
        }
    }


}
