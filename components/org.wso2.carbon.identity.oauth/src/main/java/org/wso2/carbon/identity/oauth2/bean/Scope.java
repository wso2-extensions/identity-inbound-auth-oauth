/*
 *  Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.wso2.carbon.identity.oauth2.bean;

import java.io.Serializable;
import java.util.Collections;
import java.util.List;

public class Scope implements Serializable {

    String name;
    String displayName;
    String description;
    List<String> bindings;

    public Scope(String name, String displayName, String description) {
        this.name = name;
        this.description = description;
        this.displayName = displayName;
    }

    public Scope(String name, String displayName, String description, List<String> bindings) {
        this.name = name;
        this.description = description;
        this.displayName = displayName;
        this.bindings = bindings;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public List<String> getBindings() {
        if (bindings == null) {
            return Collections.emptyList();
        }
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

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("Scope {\n");
        sb.append("  name: ").append(this.name).append("\n");
        sb.append("  displayName: ").append(this.displayName).append("\n");
        sb.append("  description: ").append(this.description).append("\n");
        sb.append("  bindings: ").append(this.bindings).append("\n");
        sb.append("}\n");
        return sb.toString();
    }
}

