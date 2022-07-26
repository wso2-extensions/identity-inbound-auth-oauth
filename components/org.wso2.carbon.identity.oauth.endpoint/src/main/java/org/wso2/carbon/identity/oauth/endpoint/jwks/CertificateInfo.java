/*
 * Copyright (c) 2022, WSO2 Inc. (http://www.wso2.com).
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

package org.wso2.carbon.identity.oauth.endpoint.jwks;

import java.security.cert.Certificate;

/**
 * Contains Certificate information
 */
public class CertificateInfo {

    private Certificate certificate;
    private Certificate[] certificateChain;
    private String certificateAlias;

    public CertificateInfo(Certificate certificate, String certificateAlias) {

        this.certificate = certificate;
        this.certificateAlias = certificateAlias;
    }

    public Certificate getCertificate() {

        return certificate;
    }

    public Certificate[] getCertificateChain() {

        return certificateChain;
    }

    public void setCertificateChain(Certificate[] certificateChain) {

        this.certificateChain = certificateChain;
    }

    public String getCertificateAlias() {

        return certificateAlias;
    }
}
