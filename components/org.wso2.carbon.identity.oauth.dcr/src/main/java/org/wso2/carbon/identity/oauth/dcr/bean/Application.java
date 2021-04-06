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
import java.util.List;

/**
 * This object contains the context related to OAuth application.
 */
public class Application implements Serializable {

    private static final long serialVersionUID = -4515815791420125411L;

    private String clientName = null;
    private String clientId = null;
    private String clientSecret = null;
    private List<String> redirectUris = null;
    private List<String> grantTypes = null;
    private List<String> aud = null;
    private String idTokenEncryptionAlgorithm = null;
    private String idTokenEncryptionMethod = null;
    private String softwareId = null;

    public String getClientName() {

        return clientName;
    }

    public void setClientName(String clientName) {

        this.clientName = clientName;
    }

    public String getClientId() {

        return clientId;
    }

    public void setClientId(String clientId) {

        this.clientId = clientId;
    }

    public String getClientSecret() {

        return clientSecret;
    }

    public void setClientSecret(String clientSecret) {

        this.clientSecret = clientSecret;
    }

    public List<String> getRedirectUris() {

        return redirectUris;
    }

    public void setRedirectUris(List<String> redirectUris) {

        this.redirectUris = redirectUris;
    }

    public List<String> getGrantTypes() {

        return grantTypes;
    }

    public void setGrantTypes(List<String> grantTypes) {

        this.grantTypes = grantTypes;
    }

    public List<String> getAud() {

        return aud;
    }

    public void setAud(List<String> aud) {

        this.aud = aud;
    }

    public String getIdTokenEncryptionAlgorithm() {

        return idTokenEncryptionAlgorithm;
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

    public String getSoftwareId() {

        return softwareId;
    }

    public void setSoftwareId(String softwareId) {

        this.softwareId = softwareId;
    }

    @Override
    public String toString() {

        return "Application {\n" +
                "  clientName: " + this.clientName + "\n" +
                "  clientId: " + this.clientId + "\n" +
                "  clientSecret: " + this.clientSecret + "\n" +
                "  redirectUris: " + this.redirectUris + "\n" +
                "  grantTypes: " + this.grantTypes + "\n" +
                "  aud: " + this.aud + "\n" +
                "  idTokenEncryptionAlgorithm: " + this.idTokenEncryptionAlgorithm + "\n" +
                "  idTokenEncryptionMethod: " + this.idTokenEncryptionMethod + "\n" +
                "  softwareId: " + this.softwareId + "\n" +
                "}\n";
    }
}
