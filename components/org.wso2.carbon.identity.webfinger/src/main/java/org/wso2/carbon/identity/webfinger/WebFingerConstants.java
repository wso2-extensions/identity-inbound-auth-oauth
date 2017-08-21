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

/**
 * This class contains all the rel types to be used in web finger.
 * Any such constants should be added in future implementations.
 */

public class WebFingerConstants {
    public static final String OPENID_CONNETCT_ISSUER_REL = "http://openid.net/specs/connect/1.0/issuer";
    public static final String CONFIG_WEBFINGER_TAG = "WebFinger";
    public static final String CONFIG_DEFAULT_SUBJECT = "Default";
    public static final String CONFIG_WEBFINGER_CONFIG = "Configuration";
    public static final String CONFIG_LINK = "Link";
    public static final String SUBJECT = "subject";
    public static final String USERINFO = "userInfo";
    public static final String LINKS = "links";
    public static final String REL = "rel";
    public static final String HREF = "href";
    public static final String RESOURCE = "resource";
    public static final String ERROR_CODE_NO_WEBFINGER_CONFIG = "webfinger_configurations_not_set";
    public static final String ERROR_CODE_INVALID_RESOURCE = "invalid_resource";
    public static final String ERROR_CODE_JSON_EXCEPTION = "json_exception";
    public static final String ERROR_CODE_INVALID_REQUEST = "invalid_request";
    public static final String ERROR_CODE_INVALID_TENANT = "invalid_tenant";
    public static final String OPENID_CONNECT_ENDPOINT = "/oauth2/oidcdiscovery";
    public static final String ERROR_MESSAGE_NO_WEBFINGER_CONFIG = "Failed to find the WebFinger Configurations.";
    public static final String ERROR_MESSAGE_INVALID_RESOURCE = "Invalid Resource found.";
    public static final String ERROR_MESSAGE_JSON_EXCEPTION = "Error occured building response.";
    public static final String ERROR_MESSAGE_INVALID_REQUEST = "Request is invalid.";
    public static final String ERROR_MESSAGE_INVALID_TENANT = "Provided tenant is invalid.";
    public static final String ACCT_SCHEME = "acct";
    public static final String RESPONSE_CONTENT_TYPE = "application/jrd+json";
}
