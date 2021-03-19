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
 * This object contains the context related to OAuth application registration request.
 */
public class ApplicationRegistrationRequest implements Serializable {

    private static final long serialVersionUID = -1766289861296661081L;

    private List<String> audiences = new ArrayList<>();
    private List<String> redirectUris = new ArrayList<>();
    private String clientName = null;
    private List<String> grantTypes = new ArrayList<>();
    private String tokenType = null;
    private String consumerKey = null;
    private String consumerSecret = null;
    private String spTemplateName = null;
    private String idTokenEncryptionAlgorithm = null;
    private String idTokenEncryptionMethod = null;
    private String tokenEndpointAuthMethod = null;
    private String backchannelLogoutUri = null;
    private String softwareId = null;

    public List<String> getAudiences() {

        return audiences;
    }

    public void setAudiences(List<String> audiences) {

        this.audiences = audiences;
    }

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

    public String getConsumerKey() {

        return consumerKey;
    }

    public void setConsumerKey(String consumerKey) {

        this.consumerKey = consumerKey;
    }

    public String getConsumerSecret() {

        return consumerSecret;
    }

    public void setConsumerSecret(String consumerSecret) {

        this.consumerSecret = consumerSecret;
    }

    public String getIdTokenEncryptionAlgorithm() {

        return  idTokenEncryptionAlgorithm;
    }

    public void setIdTokenEncryptionAlgorithm(String idTokenEncryptionAlgorithm) {

        this.idTokenEncryptionAlgorithm = idTokenEncryptionAlgorithm;
    }

    public String getIdTokenEncryptionMethod() {

        return idTokenEncryptionMethod;
    }

    public void setIdTokenEncryptionMethod(String idTokenEncryptionMethod) {

        this.idTokenEncryptionMethod = idTokenEncryptionMethod;
    }

    public String getTokenEndpointAuthMethod() {

        return tokenEndpointAuthMethod;
    }

    public void setTokenEndpointAuthMethod(String tokenEndpointAuthMethod) {

        this.tokenEndpointAuthMethod = tokenEndpointAuthMethod;
    }

    public String getBackchannelLogoutUri() {

        return backchannelLogoutUri;
    }

    public void setBackchannelLogoutUri(String backchannelLogoutUri) {

        this.backchannelLogoutUri = backchannelLogoutUri;
    }

    public String getSoftwareId() {

        return softwareId;
    }

    public void setSoftwareId(String softwareId) {

        this.softwareId = softwareId;
    }

    /**
     * Get SP template name.
     *
     * @return sp template name
     */
    public String getSpTemplateName() {

        return spTemplateName;
    }

    /**
     * Set SP template name.
     *
     * @param spTemplateName sp template name
     */
    public void setSpTemplateName(String spTemplateName) {

        this.spTemplateName = spTemplateName;
    }
}
