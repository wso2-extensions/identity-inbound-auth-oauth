/*
 * Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth2.device.util;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth2.device.constants.Constants;

/**
 * Util class which contains common methods used in Device Flow Grant.
 */
public class DeviceFlowUtil {

    private static final Log log = LogFactory.getLog(DeviceFlowUtil.class);
    static String configuredExpiresInValue = IdentityUtil.getProperty(Constants.EXPIRY_TIME_PATH);

    /**
     * Returns the configured expiry time.
     *
     * @return CONFIGURED_EXPIRES_IN_VALUE.
     */
    public static long getConfiguredExpiryTime() {

        if (log.isDebugEnabled()) {
            log.debug("User defined expiry time : " + configuredExpiresInValue);
        }
        return ((StringUtils.isNumeric(configuredExpiresInValue)) ?
                Long.parseLong(configuredExpiresInValue) : Constants.EXPIRES_IN_MILLISECONDS);
    }

    public static long getIntervalValue() {

        return (Constants.INTERVAL_MILLISECONDS / 1000);
    }
}
