/*
 *  Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
 *
 *  WSO2 LLC. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */

package org.wso2.carbon.identity.oauth2.impersonation.services;

import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.impersonation.models.ImpersonationNotificationRequestDTO;

/**
 * Service interface for managing impersonation notifications. This interface defines the contract for notifying
 * about impersonation events, including the necessary details required to process and send notifications.
 */
public interface ImpersonationNotificationMgtService {

    /**
     * Notifies about an impersonation event using the details provided in the ImpersonationNotificationRequestDTO.
     * This method handles the process of sending notifications when an impersonation occurs.
     *
     * @param impersonationNotificationRequestDTO The DTO containing details of the impersonation event.
     * @throws IdentityOAuth2Exception If there is an error while processing the notification request.
     */
    public void notifyImpersonation(ImpersonationNotificationRequestDTO impersonationNotificationRequestDTO)
            throws IdentityOAuth2Exception;
}
