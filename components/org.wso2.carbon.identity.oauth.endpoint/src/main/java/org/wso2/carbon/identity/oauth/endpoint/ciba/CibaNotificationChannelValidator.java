/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.endpoint.ciba;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.endpoint.exception.CibaAuthFailureException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Shared validator for CIBA notification channel validation.
 * Used by both JWT-based and parameter-based request paths.
 */
public class CibaNotificationChannelValidator {

    private static final Log log =
            LogFactory.getLog(CibaNotificationChannelValidator.class);

    private CibaNotificationChannelValidator() {

    }

    /**
     * Validates whether the given notification channel is allowed
     * for the application identified by the client ID.
     *
     * @param notificationChannel Notification channel to validate.
     * @param clientId            Client ID of the application.
     * @param tenantDomain        Tenant domain.
     * @throws CibaAuthFailureException If the channel is not allowed
     *                                  or an error occurs.
     */
    public static void validateChannelForClient(
            String notificationChannel, String clientId,
            String tenantDomain) throws CibaAuthFailureException {

        OAuthAppDO appDO;
        try {
            appDO = OAuth2Util
                    .getAppInformationByClientId(clientId, tenantDomain);
        } catch (IdentityOAuth2Exception
                 | InvalidOAuthClientException e) {
            throw new CibaAuthFailureException(
                    OAuth2ErrorCodes.SERVER_ERROR,
                    "Error while validating notification channel.", e);
        }

        String allowedChannelsStr = appDO.getCibaNotificationChannels();
        if (StringUtils.isNotBlank(allowedChannelsStr)) {
            List<String> allowedChannels = Arrays
                    .stream(allowedChannelsStr.split(","))
                    .map(s -> s.trim().toLowerCase())
                    .collect(Collectors.toList());

            if (!allowedChannels.contains(
                    notificationChannel.toLowerCase())) {
                if (log.isDebugEnabled()) {
                    log.debug("Requested notification channel '"
                            + notificationChannel
                            + "' is not allowed for client: " + clientId);
                }
                throw new CibaAuthFailureException(
                        OAuth2ErrorCodes.INVALID_REQUEST,
                        "Requested notification channel is not "
                                + "allowed for this application.");
            }
        }
    }
}
