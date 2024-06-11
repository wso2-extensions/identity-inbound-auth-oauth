/*
 * Copyright (c) 2024, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
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

package org.wso2.carbon.identity.oauth2.impersonation.models;

/**
 * The ImpersonationConfig class handles the configuration for impersonation settings.
 */
public class ImpersonationConfig {

    // A flag to enable or disable email notifications for impersonation actions.
    private boolean enableEmailNotification;

    /**
     * Gets the current status of email notifications.
     *
     * @return true if email notifications are enabled, false otherwise.
     */
    public boolean isEnableEmailNotification() {

        return enableEmailNotification;
    }

    /**
     * Sets the status of email notifications.
     *
     * @param enableEmailNotification true to enable email notifications, false to disable them.
     */
    public void setEnableEmailNotification(boolean enableEmailNotification) {

        this.enableEmailNotification = enableEmailNotification;
    }
}

