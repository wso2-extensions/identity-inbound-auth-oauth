/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.oauth2.model;

/**
 * This is used to store the supported token issuer configuration details from the identity.xml.
 * <p>
 * i.e:
 * <SupportedTokenTypes>
 *     <SupportedTokenType>
 *         <TokenTypeName>Default</TokenTypeName>
 *         <TokenTypeImplClass>org.wso2.carbon.identity.oauth2.token.OauthTokenIssuerImpl</TokenTypeImplClass>
 *         <PersistAccessTokenAlias>true</PersistAccessTokenAlias>
 *     </SupportedTokenType>
 * </SupportedTokenTypes>
 */
public class TokenIssuerDO {

    private String tokenType;
    private String accessTokenType;
    private String tokenImplClass;
    private boolean persistAccessTokenAlias;

    public TokenIssuerDO(String tokenType, String tokenImplClass, boolean persistAccessTokenAlias) {
        this.tokenType = tokenType;
        this.tokenImplClass = tokenImplClass;
        this.persistAccessTokenAlias = persistAccessTokenAlias;
    }

    public TokenIssuerDO(String tokenType, String tokenImplClass) {
        this.tokenType = tokenType;
        this.tokenImplClass = tokenImplClass;
    }

    public TokenIssuerDO() {
    }

    /**
     * @deprecated Use {@link #getAccessTokenType()} instead.
     */
    @Deprecated
    public String getTokenType() {
        return tokenType;
    }

    /**
     * @deprecated Use {@link #setAccessTokenType(String)} instead.
     */
    @Deprecated
    public void setTokenType(String tokenType) {
        this.tokenType = tokenType;
    }

    /**
     * Get the token issuer name.
     * @return the token issuer name
     */
    public String getTokenIssuerName() {
        return tokenType;
    }

    /**
     * Set the token issuer name.
     * @param tokenIssuerName the token issuer name to set
     */
    public void setTokenIssuerName(String tokenIssuerName) {
        this.tokenType = tokenIssuerName;
    }

    public String getAccessTokenType() {
        return accessTokenType;
    }

    public void setAccessTokenType(String accessTokenType) {
        this.accessTokenType = accessTokenType;
    }

    public String getTokenImplClass() {
        return tokenImplClass;
    }

    public void setTokenImplClass(String tokenImplClass) {
        this.tokenImplClass = tokenImplClass;
    }

    public boolean isPersistAccessTokenAlias() {
        return persistAccessTokenAlias;
    }

    public void setPersistAccessTokenAlias(boolean persistAccessTokenAlias) {
        this.persistAccessTokenAlias = persistAccessTokenAlias;
    }
}
