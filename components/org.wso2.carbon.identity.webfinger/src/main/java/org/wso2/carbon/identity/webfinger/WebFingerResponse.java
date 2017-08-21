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

package org.wso2.carbon.identity.webfinger;


import java.util.ArrayList;
import java.util.List;

/**
 * WebFingerResponse contains the required information,
 * subject and set of WebLinks as specified in OpenID Connect Discovery spec
 */
public class WebFingerResponse {
    private String subject;
    private List<WebLink> links;

    public WebFingerResponse() {
        links = new ArrayList<WebLink>();
    }

    public List<WebLink> getLinks() {
        return links;
    }

    public String getSubject() {
        return subject;
    }

    public void setSubject(String subject) {
        this.subject = subject;
    }

    public void addLink(String rel, String href) {
        WebLink link = new WebLink();
        link.setRel(rel);
        link.setHref(href);
        this.links.add(link);
    }

}
