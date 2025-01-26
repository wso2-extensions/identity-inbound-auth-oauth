/*
 * Copyright (c) 2025, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth.rar.exception;

import org.wso2.carbon.identity.base.IdentityException;

/**
 * Exception class to represent failures related to Rich Authorization Requests in OAuth 2.0 clients.
 *
 * <p>This exception is thrown when there are errors in processing authorization details during the OAuth 2.0
 * authorization flow. It extends the {@link IdentityException} class, providing more specific
 * context for authorization-related issues.</p>
 */
public class AuthorizationDetailsProcessingException extends IdentityException {

    private static final long serialVersionUID = -206212512259482200L;

    /**
     * Constructs a new exception with the specified detail message.
     *
     * @param message The detail message. It provides information about the cause of the exception.
     */
    public AuthorizationDetailsProcessingException(final String message) {

        super(message);
    }

    /**
     * Constructs a new exception with the specified detail message and cause.
     *
     * @param message The detail message. It provides information about the cause of the exception.
     * @param cause   The cause of the exception. It can be used to retrieve the stack trace or other information
     *                about the root cause of the exception.
     */
    public AuthorizationDetailsProcessingException(final String message, final Throwable cause) {

        super(message, cause);
    }
}
