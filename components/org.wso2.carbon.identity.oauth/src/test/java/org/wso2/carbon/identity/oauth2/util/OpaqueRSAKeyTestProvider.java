/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
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

package org.wso2.carbon.identity.oauth2.util;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.spec.AlgorithmParameterSpec;

/**
 * Test JCA provider that simulates an HSM. The RSA private key stays inside the provider. Callers only get an
 * opaque {@link PrivateKey} handle that does not implement {@link java.security.interfaces.RSAPrivateKey} and has no
 * encoding, like a sensitive SunPKCS11 key. Only this provider can sign with the handle.
 */
public class OpaqueRSAKeyTestProvider extends Provider {

    private static final long serialVersionUID = 1L;
    private static final String[] SIGNATURE_ALGORITHMS =
            {"SHA256withRSA", "SHA384withRSA", "SHA512withRSA", "RSASSA-PSS"};

    private final transient KeyPair keyPair;
    private final transient OpaqueRSAPrivateKey handle = new OpaqueRSAPrivateKey();

    public OpaqueRSAKeyTestProvider(int keySize) throws NoSuchAlgorithmException {

        super("OpaqueRSATest", "1.0", "Test provider that keeps RSA private keys inside the provider");
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(keySize);
        keyPair = generator.generateKeyPair();
        for (String algorithm : SIGNATURE_ALGORITHMS) {
            putService(new SignatureService(this, algorithm));
        }
    }

    /**
     * @return Opaque handle to the private key held by this provider.
     */
    public PrivateKey getPrivateKey() {

        return handle;
    }

    /**
     * @return Public key matching the private key held by this provider.
     */
    public PublicKey getPublicKey() {

        return keyPair.getPublic();
    }

    /**
     * Opaque private key handle: RSA algorithm, no encoding, not an RSAPrivateKey.
     */
    public static final class OpaqueRSAPrivateKey implements PrivateKey {

        private static final long serialVersionUID = 1L;

        @Override
        public String getAlgorithm() {

            return "RSA";
        }

        @Override
        public String getFormat() {

            return null;
        }

        @Override
        public byte[] getEncoded() {

            return null;
        }
    }

    private static final class SignatureService extends Service {

        SignatureService(OpaqueRSAKeyTestProvider provider, String algorithm) {

            super(provider, "Signature", algorithm, OpaqueKeySignatureSpi.class.getName(), null, null);
        }

        @Override
        public Object newInstance(Object constructorParameter) {

            return new OpaqueKeySignatureSpi((OpaqueRSAKeyTestProvider) getProvider(), getAlgorithm());
        }
    }

    /**
     * Signature SPI that accepts only the provider's own handle and signs with the key held inside the provider.
     */
    private static final class OpaqueKeySignatureSpi extends SignatureSpi {

        private final OpaqueRSAKeyTestProvider provider;
        private final String algorithm;
        private AlgorithmParameterSpec parameterSpec;
        private Signature delegate;

        OpaqueKeySignatureSpi(OpaqueRSAKeyTestProvider provider, String algorithm) {

            this.provider = provider;
            this.algorithm = algorithm;
        }

        @Override
        protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {

            if (privateKey != provider.handle) {
                throw new InvalidKeyException("Only keys held by this provider are supported.");
            }
            try {
                delegate = Signature.getInstance(algorithm, "SunRsaSign");
                if (parameterSpec != null) {
                    delegate.setParameter(parameterSpec);
                }
                delegate.initSign(provider.keyPair.getPrivate());
            } catch (Exception e) {
                throw new InvalidKeyException("Error while initializing the delegate signature.", e);
            }
        }

        @Override
        protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {

            throw new InvalidKeyException("Verification is not supported by this test provider.");
        }

        @Override
        protected void engineSetParameter(AlgorithmParameterSpec params) throws InvalidAlgorithmParameterException {

            parameterSpec = params;
            if (delegate != null) {
                delegate.setParameter(params);
            }
        }

        @Override
        protected void engineUpdate(byte b) throws SignatureException {

            delegate.update(b);
        }

        @Override
        protected void engineUpdate(byte[] bytes, int off, int len) throws SignatureException {

            delegate.update(bytes, off, len);
        }

        @Override
        protected byte[] engineSign() throws SignatureException {

            return delegate.sign();
        }

        @Override
        protected boolean engineVerify(byte[] sigBytes) throws SignatureException {

            throw new SignatureException("Verification is not supported by this test provider.");
        }

        @Override
        @Deprecated
        protected void engineSetParameter(String param, Object value) {

            throw new InvalidParameterException("Not supported.");
        }

        @Override
        @Deprecated
        protected Object engineGetParameter(String param) {

            throw new InvalidParameterException("Not supported.");
        }
    }
}
