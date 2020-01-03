/*
 * Copyright (c) 2010, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.token.handlers.grant.iwa.ntlm.util;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

/**
 * This is the implementation class of the javax.servlet.FilterChain.
 */
public class SimpleFilterChain implements FilterChain {

    private ServletRequest request;
    private ServletResponse response;

    /**
     * @param sreq servelt request.
     * @param srep servelt response.
     * @throws java.io.IOException
     * @throws ServletException
     */
    @Override
    public void doFilter(final ServletRequest sreq, final ServletResponse srep) throws IOException, ServletException {
        this.request = sreq;
        this.response = srep;
    }

    /**
     * This will return servlet request
     *
     * @return request.
     */
    public ServletRequest getRequest() {
        return this.request;
    }

    /**
     * This will return response.
     *
     * @return response.
     */
    public ServletResponse getResponse() {
        return this.response;
    }
}
