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

package org.wso2.carbon.identity.oauth2.token.bindings;

/**
 * This class provides the token binding implementation.
 */
public class TokenBinding {

    private String tokenId;

    private String bindingType;

    private String bindingReference;

    private String bindingValue;

    public TokenBinding() {

    }

    public TokenBinding(String tokenId, String bindingType, String bindingReference, String bindingValue) {

        this.tokenId = tokenId;
        this.bindingType = bindingType;
        this.bindingReference = bindingReference;
        this.bindingValue = bindingValue;
    }

    public TokenBinding(String bindingType, String bindingReference, String bindingValue) {

        this.bindingType = bindingType;
        this.bindingReference = bindingReference;
        this.bindingValue = bindingValue;
    }

    public TokenBinding(String bindingType, String bindingReference) {

        this.bindingType = bindingType;
        this.bindingReference = bindingReference;
    }

    public String getTokenId() {

        return tokenId;
    }

    public void setTokenId(String tokenId) {

        this.tokenId = tokenId;
    }

    public String getBindingType() {

        return bindingType;
    }

    public void setBindingType(String bindingType) {

        this.bindingType = bindingType;
    }

    public String getBindingReference() {

        return bindingReference;
    }

    public void setBindingReference(String bindingReference) {

        this.bindingReference = bindingReference;
    }

    public String getBindingValue() {

        return bindingValue;
    }

    public void setBindingValue(String bindingValue) {

        this.bindingValue = bindingValue;
    }

    @Override
    public String toString() {
        return "[Token Id: " + tokenId + ", Binding Type: " + bindingType + ", Binding Reference: " + bindingReference
                + ", Binding Value: " + bindingValue + "]";
    }
}
