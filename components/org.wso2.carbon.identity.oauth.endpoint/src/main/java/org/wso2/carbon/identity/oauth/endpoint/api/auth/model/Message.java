/*
 * Copyright (c) 2023, WSO2 LLC. (https://www.wso2.com) All Rights Reserved.
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.endpoint.api.auth.model;

import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;

import java.util.ArrayList;
import java.util.List;

/**
 * Class containing the data related to a message.
 */
public class Message {

    private FrameworkConstants.AuthenticatorMessageType type;
    private String messageId;
    private String message;
    private String i18nKey;
    private List<Context> context = new ArrayList<>();

    public Message() {

    }

    public Message(FrameworkConstants.AuthenticatorMessageType type, String messageId, String message, String i18nKey,
                   List<Context> context) {

        this.type = type;
        this.messageId = messageId;
        this.message = message;
        this.i18nKey = i18nKey;
        this.context = context;
    }

    public FrameworkConstants.AuthenticatorMessageType getType() {

        return type;
    }

    public void setType(FrameworkConstants.AuthenticatorMessageType type) {

        this.type = type;
    }

    public String getMessageId() {

        return messageId;
    }

    public void setMessageId(String messageId) {

        this.messageId = messageId;
    }

    public String getMessage() {

        return message;
    }

    public void setMessage(String message) {

        this.message = message;
    }

    public String getI18nKey() {

        return i18nKey;
    }

    public void setI18nKey(String i18nKey) {

        this.i18nKey = i18nKey;
    }

    public List<Context> getContext() {

        return context;
    }

    public void setContext(List<Context> context) {

        this.context = context;
    }
}

