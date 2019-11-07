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

package org.wso2.carbon.identity.oauth2.bean;

import java.io.Serializable;
import java.util.List;

public class ScopeBinding implements Serializable {

    private String bindingType;
    private List<String> bindings;

    public ScopeBinding(String bindingType, List<String> bindings) {

        this.bindingType = bindingType;
        this.bindings = bindings;
    }

    public String getBindingType() {

        return bindingType;
    }

    public void setBindingType(String bindingType) {

        this.bindingType = bindingType;
    }

    public List<String> getBindings() {

        return bindings;
    }

    public void setBindings(List<String> bindings) {

        this.bindings = bindings;
    }

    public void addBindings(List<String> bindings) {

        this.bindings.addAll(bindings);
    }

    public void addBinding(String binding) {

        this.bindings.add(binding);
    }

    @Override
    public String toString() {

        return String.format("ScopeBinding {\n  bindingType: %s\n  bindings: %s\n}\n", this.bindingType, this.bindings);
    }
}

