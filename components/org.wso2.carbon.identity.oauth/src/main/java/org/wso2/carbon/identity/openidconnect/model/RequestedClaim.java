/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
package org.wso2.carbon.identity.openidconnect.model;

import java.io.Serializable;
import java.util.List;

/**
 * This class contains claim object which comes with the request object parameter value in OIDC authorization request.
 */

public class RequestedClaim implements Serializable {

    private static final long serialVersionUID = 6372165740005867083L;

    private String name;
    private String type;
    private boolean isEssential;
    private String value;
    private List<String> values;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String  getType() {
        return type;
    }

    public void setType(String isUserInfo) {
        this.type = isUserInfo;
    }

    public boolean isEssential() {
        return isEssential;
    }

    public void setEssential(boolean isEssential) {
        this.isEssential = isEssential;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

    public List<String> getValues() {
        return values;
    }

    public void setValues(List<String> values) {
        this.values = values;
    }
}
