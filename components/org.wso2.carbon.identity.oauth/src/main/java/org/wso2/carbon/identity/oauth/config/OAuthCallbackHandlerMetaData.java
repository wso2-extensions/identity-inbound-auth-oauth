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

package org.wso2.carbon.identity.oauth.config;

import java.util.Properties;

/**
 * OAuth callback handler meta data.
 */
public class OAuthCallbackHandlerMetaData {

    private int priority;

    private Properties properties;

    private String className;

    public OAuthCallbackHandlerMetaData(String className, Properties properties, int priority) {
        this.priority = priority;
        this.properties = properties;
        this.className = className;
    }

    public int getPriority() {
        return priority;
    }

    public Properties getProperties() {
        return properties;
    }

    public String getClassName() {
        return className;
    }
}
