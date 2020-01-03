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

import org.apache.catalina.connector.Response;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Simple HTTP Response.
 */
public class SimpleHttpResponse extends Response {

    private int status = 500;
    private Map<String, List<String>> headers = new HashMap<String, List<String>>();
    private static final Log log = LogFactory.getLog(SimpleHttpResponse.class);

    @Override
    public int getStatus() {

        return status;
    }

    @Override
    public void setStatus(int value) {

        status = value;
    }

    @Override
    public void addHeader(String headerName, String headerValue) {

        List<String> current = headers.get(headerName);
        if (current == null) {
            current = new ArrayList<>();
        }
        current.add(headerValue);
        headers.put(headerName, current);
    }

    @Override
    public void setHeader(String headerName, String headerValue) {

        List<String> current = headers.get(headerName);
        if (current == null) {
            current = new ArrayList<String>();
        } else {
            current.clear();
        }
        current.add(headerValue);
        headers.put(headerName, current);
    }

    public String getStatusString() {

        if (status == 401) {
            return "Unauthorized";
        }
        return "Unknown";
    }

    @Override
    public void flushBuffer() {

        if (log.isDebugEnabled()) {
            log.debug(status + " " + getStatusString());
            for (Map.Entry<String, List<String>> headerEntry : headers.entrySet()) {
                for (String valueEntry : headerEntry.getValue()) {
                    log.debug(headerEntry.getKey() + ": " + valueEntry);
                }
            }
        }
    }

    public String[] getHeaderValues(String headerName) {

        List<String> headerValues = headers.get(headerName);
        return headerValues == null ? null : headerValues
                .toArray(new String[0]);
    }

    @Override
    public String getHeader(String headerName) {

        List<String> headerValues = headers.get(headerName);
        if (headerValues == null) {
            return null;
        }
        StringBuilder sb = new StringBuilder();
        for (String headerValue : headerValues) {
            if (sb.length() > 0) {
                sb.append(", ");
            }
            sb.append(headerValue);
        }
        return sb.toString();
    }

    @Override
    public Collection<String> getHeaderNames() {

        return headers.keySet();
    }

    @Override
    public void sendError(int rc, String message) {

        status = rc;
    }

    @Override
    public void sendError(int rc) {

        status = rc;
    }
}
