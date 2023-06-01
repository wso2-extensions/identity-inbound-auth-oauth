/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth.dcr.bean;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

/**
 * This object contains the context related to OAuth application update request.
 */
public class ApplicationUpdateRequest implements Serializable {

    private static final long serialVersionUID = 262481020746102240L;

    private List<String> redirectUris = new ArrayList<>();
    private String clientName = null;
    private List<String> grantTypes = new ArrayList<>();
    private String tokenType = null;
    private String backchannelLogoutUri = null;
    private String extApplicationDisplayName = null;
    private String extApplicationOwner = null;
    private Long extApplicationTokenLifetime = null;
    private Long extUserTokenLifetime = null;
    private Long extRefreshTokenLifetime = null;
    private Long extIdTokenLifetime = null;
    private boolean extPkceMandatory = false;
    private boolean extPkceSupportPlain = false;
    private boolean extPublicClient = false;

    public List<String> getRedirectUris() {

        return redirectUris;
    }

    public void setRedirectUris(List<String> redirectUris) {

        this.redirectUris = redirectUris;
    }

    public String getClientName() {

        return clientName;
    }

    public void setClientName(String clientName) {

        this.clientName = clientName;
    }

    public List<String> getGrantTypes() {

        return grantTypes;
    }

    public void setGrantTypes(List<String> grantTypes) {

        this.grantTypes = grantTypes;
    }

    public String getTokenType() {

        return tokenType;
    }

    public void setTokenType(String tokenType) {

        this.tokenType = tokenType;
    }

    public String getBackchannelLogoutUri() {

        return backchannelLogoutUri;
    }

    public void setBackchannelLogoutUri(String backchannelLogoutUri) {

        this.backchannelLogoutUri = backchannelLogoutUri;
    }

    /**
     * Get the external application display name.
     * @return external application display name.
     */
    public String getExtApplicationDisplayName() {

        return extApplicationDisplayName;
    }

    /**
     * Set the external application display name.
     * @param extApplicationDisplayName external application display name.
     */
    public void setExtApplicationDisplayName(String extApplicationDisplayName) {

        this.extApplicationDisplayName = extApplicationDisplayName;
    }

    /**
     * Get the external application owner.
     * @return external application owner.
     */
    public String getExtApplicationOwner() {

        return extApplicationOwner;
    }

    /**
     * Set the external application owner.
     * @param extApplicationOwner external application owner.
     */
    public void setExtApplicationOwner(String extApplicationOwner) {

        this.extApplicationOwner = extApplicationOwner;
    }

    /**
     * Get the external application token lifetime.
     * @return external application token lifetime.
     */
    public Long getExtApplicationTokenLifetime() {

        return extApplicationTokenLifetime;
    }

    /**
     * Set the external application token lifetime.
     * @param extApplicationTokenLifetime external application token lifetime.
     */
    public void setExtApplicationTokenLifetime(Long extApplicationTokenLifetime) {

        this.extApplicationTokenLifetime = extApplicationTokenLifetime;
    }

    /**
     * Get the external user token lifetime.
     * @return external user token lifetime.
     */
    public Long getExtUserTokenLifetime() {

        return extUserTokenLifetime;
    }

    /**
     * Set the external user token lifetime.
     * @param extUserTokenLifetime external user token lifetime.
     */
    public void setExtUserTokenLifetime(Long extUserTokenLifetime) {

        this.extUserTokenLifetime = extUserTokenLifetime;
    }

    /**
     * Get the external refresh token lifetime.
     * @return external refresh token lifetime.
     */
    public Long getExtRefreshTokenLifetime() {

        return extRefreshTokenLifetime;
    }

    /**
     * Set the external refresh token lifetime.
     * @param extRefreshTokenLifetime external refresh token lifetime.
     */
    public void setExtRefreshTokenLifetime(Long extRefreshTokenLifetime) {

        this.extRefreshTokenLifetime = extRefreshTokenLifetime;
    }

    /**
     * Get the external id token lifetime.
     * @return external id token lifetime.
     */
    public Long getExtIdTokenLifetime() {

        return extIdTokenLifetime;
    }

    /**
     * Set the external id token lifetime.
     * @param extIdTokenLifetime external id token lifetime.
     */
    public void setExtIdTokenLifetime(Long extIdTokenLifetime) {

        this.extIdTokenLifetime = extIdTokenLifetime;
    }

    /**
     * Get whether the external PKCE is mandatory or not.
     * @return whether the external PKCE is mandatory or not.
     */
    public boolean isExtPkceMandatory() {

        return extPkceMandatory;
    }

    /**
     * Set whether the external PKCE is mandatory or not.
     * @param extPkceMandatory whether the external PKCE is mandatory or not.
     */
    public void setExtPkceMandatory(boolean extPkceMandatory) {

        this.extPkceMandatory = extPkceMandatory;
    }

    /**
     * Get whether the external PKCE supports "plain" challenge method or not.
     * @return whether the external PKCE supports "plain" challenge method or not.
     */
    public boolean isExtPkceSupportPlain() {

        return extPkceSupportPlain;
    }

    /**
     * Set whether the external PKCE supports "plain" challenge method or not.
     * @param extPkceSupportPlain whether the external PKCE supports "plain" challenge method or not.
     */
    public void setExtPkceSupportPlain(boolean extPkceSupportPlain) {

        this.extPkceSupportPlain = extPkceSupportPlain;
    }

    /**
     * Get whether the client is a public client or not.
     * @return whether the client is a public client or not.
     */
    public boolean isExtPublicClient() {

        return extPublicClient;
    }

    /**
     * Set whether the client is a public client or not.
     * @param extPublicClient whether the client is a public client or not.
     */
    public void setExtPublicClient(boolean extPublicClient) {

        this.extPublicClient = extPublicClient;
    }
}
