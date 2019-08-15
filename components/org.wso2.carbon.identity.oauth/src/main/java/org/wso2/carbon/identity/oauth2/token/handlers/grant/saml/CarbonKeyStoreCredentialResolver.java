/*
 * Copyright (c) 2013, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth2.token.handlers.grant.saml;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.credential.KeyStoreCredentialResolver;
import org.opensaml.xml.security.criteria.EntityIDCriteria;
import org.wso2.carbon.identity.oauth2.util.X509CredentialImpl;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class CarbonKeyStoreCredentialResolver extends KeyStoreCredentialResolver {

    private static final Log log = LogFactory.getLog(CarbonKeyStoreCredentialResolver.class);

    private KeyStore keyStore = null;
    private Set<Credential> credentialSet = null;

    public CarbonKeyStoreCredentialResolver(KeyStore store, Map<String, String> passwords) throws IllegalArgumentException {
        super(store, passwords);
        this.keyStore = store;
    }

    @Override
    public Iterable<Credential> resolveFromSource(CriteriaSet criteriaSet) throws SecurityException {
        try {
            credentialSet = new HashSet<Credential>();
            Enumeration<String> en = keyStore.aliases();
            while (en.hasMoreElements()) {
                String alias = en.nextElement();
                X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
                Credential credential = new X509CredentialImpl(cert);
                if (criteriaSet.get(EntityIDCriteria.class) != null) {
                    if (criteriaSet.get(EntityIDCriteria.class).getEntityID().equals(alias)) {
                        credentialSet.add(credential);
                        break;
                    }
                } else {
                    credentialSet.add(credential);
                }
            }
            return credentialSet;
        } catch (KeyStoreException e) {
            log.error(e);
            throw new SecurityException("Error reading certificates from key store");
        }
    }
}
