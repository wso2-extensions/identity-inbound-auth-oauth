/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.webfinger.servlet;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.base.ServerConfigurationException;
import org.wso2.carbon.identity.webfinger.WebFingerConstants;
import org.wso2.carbon.identity.webfinger.WebFingerEndpointException;
import org.wso2.carbon.identity.webfinger.WebFingerProcessor;
import org.wso2.carbon.identity.webfinger.builders.WebFingerResponseBuilder;
import org.wso2.carbon.identity.webfinger.internal.WebFingerServiceComponentHolder;

import java.io.IOException;
import java.io.PrintWriter;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Webfinger endpoint. Servelet is registered for the path /.well-known/webfinger
 */
public class WebFingerServlet extends HttpServlet {
    private static final Log log = LogFactory.getLog(WebFingerServlet.class);

    @Override
    protected void doGet(HttpServletRequest httpServletRequest,
                         HttpServletResponse httpServletResponse) throws IOException {
        getOIDProviderIssuer(httpServletRequest, httpServletResponse);
    }

    public void getOIDProviderIssuer(HttpServletRequest httpServletRequest,
                                     HttpServletResponse httpServletResponse) throws IOException {
        WebFingerProcessor processor = WebFingerServiceComponentHolder.getWebFingerProcessor();
        String response = "";
        try {
            WebFingerResponseBuilder webFingerResponseBuilder = new JSONResponseBuilder();
            response = webFingerResponseBuilder.getOIDProviderIssuerString(processor.getResponse(httpServletRequest));
        } catch (WebFingerEndpointException e) {
            httpServletResponse.setStatus(processor.handleError(e));
            return;
        } catch (ServerConfigurationException e) {
            log.error("Server Configuration error occurred.", e);
            httpServletResponse.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            return;
        }
        httpServletResponse.setContentType(WebFingerConstants.RESPONSE_CONTENT_TYPE);
        PrintWriter out = httpServletResponse.getWriter();
        out.print(response);
    }
}
