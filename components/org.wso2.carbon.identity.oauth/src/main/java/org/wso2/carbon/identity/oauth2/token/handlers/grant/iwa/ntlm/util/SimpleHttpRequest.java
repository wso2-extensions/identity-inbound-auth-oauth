/*
 * Copyright (c) 2013, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth2.token.handlers.grant.iwa.ntlm.util;

import org.apache.catalina.connector.Connector;
import org.apache.catalina.connector.Request;

import java.security.Principal;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpSession;

/**
 * Simple HTTP request.
 */
public class SimpleHttpRequest extends Request {

    private static int remotePorts = 0;

    private String requestURI = null;
    private String queryString = null;
    private String remoteUser = null;
    private String method = "GET";
    private String remoteHost = null;
    private String remoteAddr = null;
    private int remotePort;
    private Map<String, String> headers = new HashMap<>();
    private Map<String, String> parameters = new HashMap<>();
    private byte[] content = null;
    private HttpSession simpleSession = new SimpleHttpSession();
    private Principal principal = null;

    public SimpleHttpRequest(Connector connector) {

        super(connector);
        remotePort = nextRemotePort();
    }

    public static synchronized int nextRemotePort() {

        return ++remotePorts;
    }

    public static synchronized void resetRemotePort() {

        remotePorts = 0;
    }

    //@Override
    public void addHeader(String headerName, String headerValue) {

        headers.put(headerName, headerValue);
    }

    @Override
    public String getHeader(String headerName) {

        return headers.get(headerName);
    }

    @Override
    public String getMethod() {

        return method;
    }

    // @Override
    public void setMethod(String methodName) {

        method = methodName;
    }

    @Override
    public int getContentLength() {

        return content == null ? -1 : content.length;
    }

    // @Override
    public void setContentLength(int length) {

        content = new byte[length];
    }

    @Override
    public int getRemotePort() {

        return remotePort;
    }

    @Override
    public String getRemoteUser() {

        return remoteUser;
    }

    public void setRemoteUser(String username) {

        remoteUser = username;
    }

    @Override
    public HttpSession getSession() {

        return simpleSession;
    }

    @Override
    public HttpSession getSession(boolean create) {

        if (simpleSession == null && create) {
            simpleSession = new SimpleHttpSession();
        }
        return simpleSession;
    }

    @Override
    public String getQueryString() {

        return queryString;
    }

    //@Override
    public void setQueryString(String queryString) {

        this.queryString = queryString;
        if (this.queryString != null) {
            for (String eachParameter : this.queryString.split("[&]")) {
                String[] pair = eachParameter.split("=");
                String value = (pair.length == 2) ? pair[1] : "";
                addParameter(pair[0], value);
            }
        }
    }

    @Override
    public String getRequestURI() {

        return requestURI;
    }

    //@Override
    public void setRequestURI(String uri) {

        requestURI = uri;
    }

    @Override
    public String getParameter(String parameterName) {

        return parameters.get(parameterName);
    }

    public void addParameter(String parameterName, String parameterValue) {

        parameters.put(parameterName, parameterValue);
    }

    @Override
    public String getRemoteHost() {

        return remoteHost;
    }

    @Override
    public void setRemoteHost(String remoteHost) {

        this.remoteHost = remoteHost;
    }

    @Override
    public String getRemoteAddr() {

        return remoteAddr;
    }

    @Override
    public void setRemoteAddr(String remoteAddr) {

        this.remoteAddr = remoteAddr;
    }

    @Override
    public Principal getUserPrincipal() {

        return principal;
    }

    @Override
    public void setUserPrincipal(Principal principal) {

        this.principal = principal;
    }
}
