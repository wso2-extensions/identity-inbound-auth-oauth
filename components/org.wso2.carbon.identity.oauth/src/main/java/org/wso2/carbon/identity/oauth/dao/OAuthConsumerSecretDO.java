/**
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.oauth.dao;

import com.fasterxml.jackson.annotation.JsonIgnore;

import java.beans.Transient;
import java.io.Serializable;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlTransient;

/**
 * OAuth Consumer Secret Data Object.
 */
@XmlAccessorType(XmlAccessType.FIELD)
public class OAuthConsumerSecretDO implements Serializable {

    private static final long serialVersionUID = 3865620852649485231L;

    @XmlTransient
    @JsonIgnore
    private String secretId;
    @XmlTransient
    @JsonIgnore
    private int consumerKeyId;
    private String secretValue;
    @XmlTransient
    @JsonIgnore
    private String secretHash;
    @XmlTransient
    @JsonIgnore
    private Long createdTime;
    private Long expiryTime;

    @Transient
    public String getSecretId() {

        return secretId;
    }

    public void setSecretId(String secretId) {

        this.secretId = secretId;
    }

    @Transient
    public int getConsumerKeyId() {

        return consumerKeyId;
    }

    public void setConsumerKeyId(int consumerKeyId) {

        this.consumerKeyId = consumerKeyId;
    }

    public String getSecretValue() {

        return secretValue;
    }

    public void setSecretValue(String secretValue) {

        this.secretValue = secretValue;
    }

    @Transient
    public String getSecretHash() {

        return secretHash;
    }

    public void setSecretHash(String secretHash) {

        this.secretHash = secretHash;
    }

    @Transient
    public Long getCreatedTime() {

        return createdTime;
    }

    public void setCreatedTime(Long createdTime) {

        this.createdTime = createdTime;
    }

    public Long getExpiryTime() {

        return expiryTime;
    }

    public void setExpiryTime(Long expiryTime) {

        this.expiryTime = expiryTime;
    }
}
