/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
package org.wso2.carbon.identity.oauth2.model;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.Enumeration;

/**
 * This class is to store all Http Request Headers
 */
public class HttpRequestHeaderHandler {

    private HttpRequestHeader[] httpRequestHeaders;
    private Cookie[] cookies;

    public HttpRequestHeaderHandler(HttpServletRequest request) {

        this.cookies = request.getCookies();
        Enumeration headerNames = request.getHeaderNames();
        if (headerNames != null) {
            ArrayList httpHeaderList;
            String headerName;
            ArrayList headerValueList;
            for (httpHeaderList = new ArrayList(); headerNames.hasMoreElements(); httpHeaderList
                    .add(new HttpRequestHeader(headerName,
                            (String[]) headerValueList.toArray(new String[headerValueList.size()])))) {
                headerName = (String) headerNames.nextElement();
                Enumeration headerValues = request.getHeaders(headerName);
                headerValueList = new ArrayList();
                if (headerValues != null) {
                    while (headerValues.hasMoreElements()) {
                        headerValueList.add((String) headerValues.nextElement());
                    }
                }
            }

            this.httpRequestHeaders =
                    (HttpRequestHeader[]) httpHeaderList.toArray(new HttpRequestHeader[httpHeaderList.size()]);
        }

    }

    public HttpRequestHeader[] getHttpRequestHeaders() {

        return this.httpRequestHeaders;
    }

    public Cookie[] getCookies() {

        return this.cookies != null ? this.cookies : null;
    }
}
