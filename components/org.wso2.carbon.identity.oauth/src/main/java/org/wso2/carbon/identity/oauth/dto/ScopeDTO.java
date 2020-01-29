/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * The model representing an OIDC scope.
 */
public class ScopeDTO implements Serializable {

    private static final long serialVersionUID = 6372165740005867083L;
    private String name;
    private String displayName;
    private String description;
    private String[] claim;

    public ScopeDTO() {

    }

    public ScopeDTO(String name, String displayName, String description, String[] claim) {

        this.name = name;
        this.displayName = displayName;
        this.description = description;
        this.claim = claim;
    }

    public String getName() {

        return name;
    }

    public void setName(String name) {

        this.name = name;
    }

    public String[] getClaim() {

        return claim;
    }

    public void setClaim(String[] claim) {

        this.claim = claim;
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

    public void addNewClaimToExistingClaims(String claimNeedToBeAdd) {

        List<String> claimsAsList = new ArrayList<String>(Arrays.asList(this.claim));
        claimsAsList.add(claimNeedToBeAdd);
        this.claim = claimsAsList.toArray(new String[0]);
    }

}
