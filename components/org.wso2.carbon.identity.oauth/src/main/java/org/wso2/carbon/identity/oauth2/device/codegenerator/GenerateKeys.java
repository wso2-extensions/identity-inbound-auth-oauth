/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth2.device.codegenerator;

import org.apache.commons.lang.RandomStringUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth2.device.constants.Constants;
import org.wso2.carbon.identity.oauth2.device.util.DeviceFlowUtil;

import java.security.SecureRandom;
import java.time.Instant;

/**
 * This class will be used to generate user code & quantifier to make user_code unique.
 */
public class GenerateKeys {

    private static final Log log = LogFactory.getLog(GenerateKeys.class);

    public GenerateKeys() {

    }

    /**
     * This method is used to generate random string with fixed length.
     *
     * @param num Length of the random string.
     * @return Random string.
     */
    public static String getKey(int num) {

        int userCodeLength;
        int keysetEnd;
        char[] subKeyset;
        int configuredUserCodeLength;
        String configuredKeySet = IdentityUtil.getProperty(Constants.CONF_KEY_SET);
        String configuredLength = IdentityUtil.getProperty(Constants.CONF_USER_CODE_LENGTH);
        try {
            configuredUserCodeLength = (StringUtils.isNotBlank(configuredLength) ? Integer.parseInt(configuredLength) :
                    Constants.KEY_LENGTH);
        } catch (NumberFormatException e) {
            log.error("Error while converting user_code length " + configuredLength + " to integer. ", e);
            configuredUserCodeLength = Constants.KEY_LENGTH;
        }
        userCodeLength = Math.max(configuredUserCodeLength, num);
        if (log.isDebugEnabled()) {
            log.debug("User defined keyset : " + configuredKeySet + " and user_code length : " +
                    configuredUserCodeLength);
        }
        if (StringUtils.isNotBlank(configuredKeySet)) {
            keysetEnd = configuredKeySet.length();
            subKeyset = configuredKeySet.toCharArray();
        } else {
            keysetEnd = Constants.KEY_SET.length();
            subKeyset = Constants.KEY_SET.toCharArray();
        }
        return RandomStringUtils.random(userCodeLength, 0, keysetEnd, false, false,
                subKeyset, new SecureRandom());
    }

    /**
     * This method is used to generate current quantifier.
     *
     * @return Current quantized time period user_code belongs.
     */
    public static long getCurrentQuantifier() {

        //https://github.com/wso2/product-is/issues/7348#issuecomment-593761350
        return (Instant.now().getEpochSecond() / (2 * DeviceFlowUtil.getConfiguredExpiryTime()));
    }
}
