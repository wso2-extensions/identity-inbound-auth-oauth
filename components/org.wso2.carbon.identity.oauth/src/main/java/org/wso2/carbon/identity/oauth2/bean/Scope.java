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

import org.apache.commons.lang.StringUtils;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.wso2.carbon.identity.oauth2.Oauth2ScopeConstants.DEFAULT_SCOPE_BINDING;

public class Scope implements Serializable {

    private String name;
    private String displayName;
    private String description;
    private List<ScopeBinding> scopeBindings = new ArrayList<>();

    public Scope(String name, String displayName, String description) {
        this.name = name;
        this.description = description;
        this.displayName = displayName;
    }

    @Deprecated
    public Scope(String name, String displayName, String description, List<String> bindings) {
        this.name = name;
        this.description = description;
        this.displayName = displayName;
        this.addScopeBindings(DEFAULT_SCOPE_BINDING, bindings);
    }

    public Scope(String name, String displayName, List<ScopeBinding> scopeBindings, String description) {
        this.name = name;
        this.description = description;
        this.displayName = displayName;
        this.scopeBindings = scopeBindings;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    @Deprecated
    public List<String> getBindings() {
        if (scopeBindings == null) {
            return Collections.emptyList();
        }
        for (ScopeBinding scopeBinding : scopeBindings) {
            if (DEFAULT_SCOPE_BINDING.equalsIgnoreCase(scopeBinding.getBindingType())) {
                return scopeBinding.getBindings();
            }
        }
        return Collections.emptyList();
    }

    @Deprecated
    public void setBindings(List<String> bindings) {
        setDefaultScopeBinding(bindings);
    }

    @Deprecated
    public void addBindings(List<String> bindings) {
        this.addScopeBindings(DEFAULT_SCOPE_BINDING, bindings);
    }

    public void addScopeBindings(String bindingType, List<String> bindings) {

        boolean bindingTypeExists = false;
        for (ScopeBinding scopeBinding : this.scopeBindings) {
            if (bindingType.equalsIgnoreCase(scopeBinding.getBindingType())) {
                bindingTypeExists = true;
                scopeBinding.getBindings().addAll(bindings);
            }
        }
        if (!bindingTypeExists) {
            ScopeBinding scopeBinding = new ScopeBinding(bindingType, bindings);
            this.scopeBindings.add(scopeBinding);
        }
    }

    public void addScopeBinding(String bindingType, String binding) {

        if (StringUtils.isBlank(bindingType)) {
            return;
        }
        boolean bindingTypeExists = false;
        for (ScopeBinding scopeBinding : this.scopeBindings) {
            if (bindingType.equalsIgnoreCase(scopeBinding.getBindingType())) {
                bindingTypeExists = true;
                if (!scopeBinding.getBindings().contains(binding)) {
                    scopeBinding.getBindings().add(binding);
                }
            }
        }
        if (!bindingTypeExists) {
            List<String> bindings = new ArrayList<>();
            bindings.add(binding);
            ScopeBinding scopeBinding = new ScopeBinding(bindingType, bindings);
            this.scopeBindings.add(scopeBinding);
        }
    }

    @Deprecated
    public void addBinding(String binding) {
        this.addScopeBinding(DEFAULT_SCOPE_BINDING, binding);
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

    public List<ScopeBinding> getScopeBindings() {

        return scopeBindings;
    }

    public void setScopeBindings(List<ScopeBinding> scopeBindings) {

        this.scopeBindings = scopeBindings;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("Scope {\n");
        sb.append("  name: ").append(this.name).append("\n");
        sb.append("  displayName: ").append(this.displayName).append("\n");
        sb.append("  description: ").append(this.description).append("\n");
        sb.append("  scopeBindings: ").append(this.scopeBindings).append("\n");
        sb.append("}\n");
        return sb.toString();
    }

    private void setDefaultScopeBinding(List<String> bindings) {

        ScopeBinding scopeBinding = new ScopeBinding(DEFAULT_SCOPE_BINDING, bindings);
        List<ScopeBinding> scopeBindings = new ArrayList<>();
        scopeBindings.add(scopeBinding);
        this.setScopeBindings(scopeBindings);
    }
}

