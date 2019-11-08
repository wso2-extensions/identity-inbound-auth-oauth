/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wso2.carbon.identity.oauth.dto;

import java.io.Serializable;
import java.util.List;

/**
 * This class represents the token binding meta data DTO.
 */
public class TokenBindingMetaDataDTO implements Serializable {

    private static final long serialVersionUID = 6372165740005823232L;

    private String displayName;

    private String description;

    private String tokenBindingType;

    private List<String> supportedGrantTypes;

    public TokenBindingMetaDataDTO() {

    }

    public TokenBindingMetaDataDTO(String displayName, String description, String tokenBindingType,
            List<String> supportedGrantTypes) {

        this.displayName = displayName;
        this.description = description;
        this.tokenBindingType = tokenBindingType;
        this.supportedGrantTypes = supportedGrantTypes;
    }

    public String getDisplayName() {

        return displayName;
    }

    public void setDisplayName(String displayName) {

        this.displayName = displayName;
    }

    public String getDescription() {

        return description;
    }

    public void setDescription(String description) {

        this.description = description;
    }

    public String getTokenBindingType() {

        return tokenBindingType;
    }

    public void setTokenBindingType(String tokenBindingType) {

        this.tokenBindingType = tokenBindingType;
    }

    public List<String> getSupportedGrantTypes() {

        return supportedGrantTypes;
    }

    public void setSupportedGrantTypes(List<String> supportedGrantTypes) {

        this.supportedGrantTypes = supportedGrantTypes;
    }
}
