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

package org.wso2.carbon.identity.oauth.dcr.util;

import org.wso2.carbon.identity.oauth.dcr.DCRMConstants;
import org.wso2.carbon.identity.oauth.dcr.exception.DCRMClientException;
import org.wso2.carbon.identity.oauth.dcr.exception.DCRMServerException;

/**
 * Error utilities related to DCR Configurations.
 */
public class DCRConfigErrorUtils {

    /**
     * Handle server exceptions.
     *
     * @param error The ErrorMessage.
     * @param data  Additional data that should be added to the error message. This is a String var-arg.
     * @return DCRMServerException instance.
     */
    public static DCRMServerException handleServerException(DCRMConstants.DCRConfigErrorMessage error, String... data) {

        return new DCRMServerException(error.getCode(), String.format(error.getDescription(), data));
    }

    /**
     * Handle server exceptions.
     *
     * @param error The ErrorMessage.
     * @param e     Original error.
     * @param data  Additional data that should be added to the error message. This is a String var-arg.
     * @return DCRMServerException instance.
     */
    public static DCRMServerException handleServerException(DCRMConstants.DCRConfigErrorMessage error, Throwable e,
                                                            String... data) {

        return new DCRMServerException(error.getCode(), String.format(error.getDescription(), data), e);
    }

    /**
     * Handle client exceptions.
     *
     * @param error The ErrorMessage.
     * @param data  Additional data that should be added to the error message. This is a String var-arg.
     * @return DCRMClientException instance.
     */
    public static DCRMClientException handleClientException(DCRMConstants.DCRConfigErrorMessage error, String... data) {

        return new DCRMClientException(error.getCode(), String.format(error.getDescription(), data));
    }

    /**
     * Handle client exceptions.
     *
     * @param error The ErrorMessage.
     * @param e     Original error.
     * @param data  Additional data that should be added to the error message. This is a String var-arg.
     * @return DCRMClientException instance.
     */
    public static DCRMClientException handleClientException(DCRMConstants.DCRConfigErrorMessage error, Throwable e,
                                                            String... data) {

        return new DCRMClientException(String.format(error.getDescription(), data), error.getCode(), e);
    }
}
