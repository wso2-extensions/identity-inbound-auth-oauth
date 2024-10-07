/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth2.device.constants;

import org.wso2.carbon.utils.security.KeystoreUtils;

/**
 * Constants that will be used in device flow.
 */
public class Constants {

    public static final String DEVICE_CODE = "device_code";
    public static final String USER_CODE = "user_code";
    public static final String EXPIRES_IN = "expires_in";
    public static final String INTERVAL = "interval";
    public static final String VERIFICATION_URI = "verification_uri";
    public static final String VERIFICATION_URI_COMPLETE = "verification_uri_complete";
    public static final String RESPONSE_TYPE = "response_type";
    public static final String CLIENT_ID = "client_id";
    public static final String SCOPE = "scope";
    public static final String RESPONSE_TYPE_DEVICE = "device";
    public static final String USED = "USED";
    public static final String DEVICE_FLOW_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code";
    public static final String AUTHORIZED = "AUTHORIZED";
    public static final String STATUS = "STATUS";
    public static final String NOT_EXIST = "NOT_EXIST";
    public static final String EXPIRY_TIME = "EXPIRY_TIME";
    public static final String PENDING = "PENDING";
    public static final String SLOW_DOWN = "SLOW_DOWN";
    public static final String AUTHZ_USER = "AUTHZ_USER";
    public static final String LAST_POLL_TIME = "LAST_POLL_TIME";
    public static final String POLL_TIME = "POLL_TIME";
    public static final String EXPIRED = "EXPIRED";
    public static final String NONCE = "nonce";
    public static final String REDIRECTION_URI = "redirect_uri";
    public static final String UTC = "UTC";
    public static final String APP_NAME = "app_name";
    public static final String SEPARATED_WITH_SPACE = " ";
    public static final String ERROR = "error";
    public static final String ERROR_DESCRIPTION = "error_description";
    public static final String DEVICE_ENDPOINT_PATH = "/authenticationendpoint/device.do";
    public static final String DEVICE_SUCCESS_ENDPOINT_PATH = "/authenticationendpoint/device_success.do";
    public static final String USERCODE_QUANTIFIER_CONSTRAINT = "USRCDE_QNTFR_CONSTRAINT";

    public static final String EXPIRY_TIME_PATH = "OAuth.SupportedGrantTypes.SupportedGrantType.ExpiryTime";
    public static final String CONF_KEY_SET = "OAuth.SupportedGrantTypes.SupportedGrantType.KeySet";
    public static final String CONF_USER_CODE_LENGTH = "OAuth.SupportedGrantTypes.SupportedGrantType.UserCodeLength";

    // Configurable values.
    public static final int KEY_LENGTH = 6;
    public static final long EXPIRES_IN_MILLISECONDS = 600000L;
    public static final int  INTERVAL_MILLISECONDS = 5000;
    public static final String KEY_SET = "BCDFGHJKLMNPQRSTVWXYZbcdfghjklmnpqrstvwxyz23456789";

    public static final int DEFAULT_DEVICE_TOKEN_PERSIST_RETRY_COUNT = 5;
    public static final String PROXY_ENABLE = "JWTValidatorConfigs.JWKSEndpoint.HTTPProxy.Enable";
    public static final String PROXY_HOST = "JWTValidatorConfigs.JWKSEndpoint.HTTPProxy.Host";
    public static final String PROXY_PORT = "JWTValidatorConfigs.JWKSEndpoint.HTTPProxy.Port";
    public static final String PROXY_USERNAME = "JWTValidatorConfigs.JWKSEndpoint.HTTPProxy.Username";
    public static final String PROXY_PASSWORD = "JWTValidatorConfigs.JWKSEndpoint.HTTPProxy.Password";
    public static final String PROTOCOL_HTTPS = "HTTPS";
    public static final String TRUSTSTORE_LOCATION = "Security.TrustStore.Location";
    public static final String TRUSTSTORE_PASSWORD = "Security.TrustStore.Password";
    public static final String TRUSTSTORE_TYPE = KeystoreUtils.getTrustStoreFileType();
}
