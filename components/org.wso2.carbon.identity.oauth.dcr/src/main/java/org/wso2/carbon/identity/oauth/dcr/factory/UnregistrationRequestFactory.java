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
package org.wso2.carbon.identity.oauth.dcr.factory;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkClientException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkRuntimeException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityRequestFactory;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.oauth.dcr.model.UnregistrationRequest;
import org.wso2.carbon.identity.oauth.dcr.util.DCRConstants;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.HttpMethod;
import javax.ws.rs.core.HttpHeaders;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;

/**
 * UnRegistration Request Factory.
 */
public class UnregistrationRequestFactory extends HttpIdentityRequestFactory {

    private static Log log = LogFactory.getLog(UnregistrationRequestFactory.class);

    @Override
    public boolean canHandle(HttpServletRequest request, HttpServletResponse response) throws
                                                                                       FrameworkRuntimeException {
        boolean canHandle = false;
        if (request != null) {
            Matcher matcher = DCRConstants.DCR_ENDPOINT_UNREGISTER_URL_PATTERN.matcher(request.getRequestURI());
            if (matcher.matches() && HttpMethod.DELETE.equals(request.getMethod())) {
                canHandle = true;
            }
        }
        if (log.isDebugEnabled()) {
            log.debug("canHandle " + canHandle + " by UnregistrationRequestFactory.");
        }
        return canHandle;
    }

    @Override
    public IdentityRequest.IdentityRequestBuilder create(HttpServletRequest request, HttpServletResponse response)
            throws FrameworkClientException {

        UnregistrationRequest.DCRUnregisterRequestBuilder unregisterRequestBuilder =
                new UnregistrationRequest.DCRUnregisterRequestBuilder();
        create(unregisterRequestBuilder, request, response);
        return unregisterRequestBuilder;

    }

    @Override
    public void create(IdentityRequest.IdentityRequestBuilder builder, HttpServletRequest request,
                       HttpServletResponse response) throws FrameworkClientException {

        UnregistrationRequest.DCRUnregisterRequestBuilder unregisterRequestBuilder = null;
        if (builder instanceof UnregistrationRequest.DCRUnregisterRequestBuilder) {
            unregisterRequestBuilder =
                    (UnregistrationRequest.DCRUnregisterRequestBuilder) builder;
            super.create(unregisterRequestBuilder, request, response);

            Map<String, String> headers = new HashMap<>();
            headers.put(HttpHeaders.AUTHORIZATION, request.getHeader(HttpHeaders.AUTHORIZATION));

            unregisterRequestBuilder.setMethod(request.getMethod());
            unregisterRequestBuilder.setHeaders(headers);

            String clientId = request.getParameter("userId");
            String applicationName = request.getParameter("applicationName");
            String consumerKey = null;
            Matcher matcher = DCRConstants.DCR_ENDPOINT_UNREGISTER_URL_PATTERN.matcher(request.getRequestURI());
            if (matcher.find()) {
                consumerKey = matcher.group(2);
            }

            unregisterRequestBuilder.setApplicationName(applicationName);
            unregisterRequestBuilder.setUserId(clientId);
            unregisterRequestBuilder.setConsumerKey(consumerKey);
        } else {
            log.error("Can't create unregisterRequestBuilder. builder is not an instance of " +
                    "UnregistrationRequest.DCRUnregisterRequestBuilder");
        }

    }

}
