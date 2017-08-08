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
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityResponse;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityResponse;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.dcr.factory.HttpRegistrationResponseFactory;
import org.wso2.carbon.identity.oauth.dcr.model.RegistrationResponse;

import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;

public class HttpOIDCRegistrationResponseFactory extends HttpRegistrationResponseFactory {

    private static Log log = LogFactory.getLog(HttpOIDCRegistrationResponseFactory.class);

    @Override
    public String getName() {
        return null;
    }

    @Override
    public HttpIdentityResponse.HttpIdentityResponseBuilder create(IdentityResponse identityResponse) {
        HttpIdentityResponse.HttpIdentityResponseBuilder httpIdentityResponseBuilder = new HttpIdentityResponse
                .HttpIdentityResponseBuilder();
        create(httpIdentityResponseBuilder, identityResponse);
        return httpIdentityResponseBuilder;
    }

    @Override
    public void create(HttpIdentityResponse.HttpIdentityResponseBuilder httpIdentityResponseBuilder,
                       IdentityResponse identityResponse) {

        RegistrationResponse registrationResponse = null;
        if (identityResponse instanceof RegistrationResponse) {
            registrationResponse = (RegistrationResponse) identityResponse;
            httpIdentityResponseBuilder.setStatusCode(HttpServletResponse.SC_CREATED);
            httpIdentityResponseBuilder.addHeader(OAuthConstants.HTTP_RESP_HEADER_CACHE_CONTROL,
                    OAuthConstants.HTTP_RESP_HEADER_VAL_CACHE_CONTROL_NO_STORE);
            httpIdentityResponseBuilder.addHeader(OAuthConstants.HTTP_RESP_HEADER_PRAGMA,
                    OAuthConstants.HTTP_RESP_HEADER_VAL_PRAGMA_NO_CACHE);
            httpIdentityResponseBuilder.addHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON);
            httpIdentityResponseBuilder.setBody(generateSuccessfulResponse(registrationResponse).toJSONString());
        } else {
            log.error("Can't create httpIdentityResponseBuilder. identityResponse is not an instance of " +
                    "RegistrationResponse");
        }
    }

    public HttpIdentityResponse.HttpIdentityResponseBuilder handleException(FrameworkException exception) {
        return super.handleException(exception);
    }

    @Override
    public boolean canHandle(IdentityResponse identityResponse) {
        if (identityResponse instanceof RegistrationResponse) {
            return true;
        }
        return false;
    }

    @Override
    public int getPriority() {
        return 50;
    }

    public boolean canHandle(FrameworkException exception) {

        return false;
    }


}
