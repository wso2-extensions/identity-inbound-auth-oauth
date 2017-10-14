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
package org.wso2.carbon.identity.oauth.dcr.factory;

import java.util.regex.Matcher;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.HttpMethod;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkClientException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityRequestFactory;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest.IdentityRequestBuilder;
import org.wso2.carbon.identity.oauth.dcr.model.ReadRequest;
import org.wso2.carbon.identity.oauth.dcr.util.DCRConstants;

/**
 * ReadRequestFactory build the request for DCRM Read Request.
 */
public class ReadRequestFactory extends HttpIdentityRequestFactory {

    private static Log log = LogFactory.getLog(ReadRequestFactory.class);

    @Override
    public boolean canHandle(HttpServletRequest request, HttpServletResponse response) {

        boolean canHandle = false;
        if (request != null) {
            Matcher matcher = DCRConstants.DCRM_ENDPOINT_CLIENT_CONFIGURATION_URL_PATTERN
                .matcher(request.getRequestURI());
            if (matcher.matches() && HttpMethod.GET.equals(request.getMethod())) {
                canHandle = true;
            }
        }
        if (log.isDebugEnabled()) {
            log.debug("canHandle " + canHandle + " by ReadRequestFactory.");
        }
        return canHandle;
    }

    @Override
    public ReadRequest.ReadRequestBuilder create(HttpServletRequest request,
        HttpServletResponse response) throws FrameworkClientException {

        ReadRequest.ReadRequestBuilder readRequestBuilder = new ReadRequest.ReadRequestBuilder();
        create(readRequestBuilder, request, response);
        return readRequestBuilder;
    }

    @Override
    public void create(IdentityRequestBuilder builder, HttpServletRequest request,
        HttpServletResponse response) throws FrameworkClientException {

        ReadRequest.ReadRequestBuilder readRequestBuilder = (ReadRequest.ReadRequestBuilder)builder;
        super.create(readRequestBuilder, request, response);

        String consumerKey = null;
        Matcher matcher = DCRConstants.DCRM_ENDPOINT_CLIENT_CONFIGURATION_URL_PATTERN
            .matcher(request.getRequestURI());
        if (matcher.find()) {
            consumerKey = matcher.group(2);
        }

        String username = CarbonContext.getThreadLocalCarbonContext().getUsername();

        readRequestBuilder.setConsumerKey(consumerKey);
        readRequestBuilder.setUsername(username);
    }

}
