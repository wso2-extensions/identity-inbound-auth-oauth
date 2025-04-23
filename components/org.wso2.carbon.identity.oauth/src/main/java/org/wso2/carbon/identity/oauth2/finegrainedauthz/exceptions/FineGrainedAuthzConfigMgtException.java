/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.oauth2.finegrainedauthz.exceptions;

/**
 * FineGrainedAuthzConfigMgtException is thrown when there is an error in managing fine-grained authorization
 * configurations.
 */
public class FineGrainedAuthzConfigMgtException extends Exception {

    private String errorCode;

    /**
     * The default constructor.
     */
    public FineGrainedAuthzConfigMgtException() {

        super();
    }

    /**
     * Constructor with {@code message}, {@code errorCode} and {@code cause} parameters.
     *
     * @param message   Message to be included in the exception.
     * @param errorCode Error code of the exception.
     * @param cause     Exception to be wrapped.
     */
    public FineGrainedAuthzConfigMgtException(String message, String errorCode, Throwable cause) {

        super(message, cause);
        this.errorCode = errorCode;
    }

    /**
     * Get the {@code errorCode}.
     *
     * @return Returns the {@code errorCode}.
     */
    public String getErrorCode() {

        return errorCode;
    }
}
