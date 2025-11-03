package org.wso2.carbon.identity.oauth2.crypto;

import com.nimbusds.jose.Requirement;


public class JWEAlgorithm {

    /**
     * RSAES using Optimal Asymmetric Encryption Padding (OAEP) (RFC 3447),
     * with the SHA-512 hash function and the MGF1 with SHA-384 mask
     * generation function.
     */
    public static final com.nimbusds.jose.JWEAlgorithm RSA_OAEP_384 = new com.nimbusds.jose.JWEAlgorithm("RSA-OAEP-384", Requirement.OPTIONAL);


    /**
     * RSAES using Optimal Asymmetric Encryption Padding (OAEP) (RFC 3447),
     * with the SHA-512 hash function and the MGF1 with SHA-512 mask
     * generation function.
     */
    public static final com.nimbusds.jose.JWEAlgorithm RSA_OAEP_512 = new com.nimbusds.jose.JWEAlgorithm("RSA-OAEP-512", Requirement.OPTIONAL);
}