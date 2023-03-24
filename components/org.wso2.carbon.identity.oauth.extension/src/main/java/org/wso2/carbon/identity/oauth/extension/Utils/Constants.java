package org.wso2.carbon.identity.oauth.extension.Utils;

public class Constants {

    public static final String OUTCOME_SUCCESS = "onSuccess";
    public static final String OUTCOME_FAIL = "onFail";
    public static final String OUTCOME_TIMEOUT = "onTimeout";

    public class CallChoreoConstants {

        public static final String TYPE_APPLICATION_JSON = "application/json";
        public static final String TYPE_FORM_DATA = "application/x-www-form-urlencoded";
        public static final String AUTHORIZATION = "Authorization";
        public static final String GRANT_TYPE = "grant_type";
        public static final String GRANT_TYPE_CLIENT_CREDENTIALS = "client_credentials";
        public static final String URL_VARIABLE_NAME = "url";
        public static final String CONSUMER_KEY_VARIABLE_NAME = "consumerKey";
        public static final String CONSUMER_KEY_ALIAS_VARIABLE_NAME = "consumerKeyAlias";
        public static final String CONSUMER_SECRET_VARIABLE_NAME = "consumerSecret";
        public static final String CONSUMER_SECRET_ALIAS_VARIABLE_NAME = "consumerSecretAlias";
        public static final String SECRET_TYPE = "ADAPTIVE_AUTH_CALL_CHOREO";
        public static final char DOMAIN_SEPARATOR = '.';
        public static final String ACCESS_TOKEN_KEY = "access_token";
        public static final int HTTP_STATUS_OK = 200;
        public static final int HTTP_STATUS_UNAUTHORIZED = 401;
        public static final String ERROR_CODE_ACCESS_TOKEN_INACTIVE = "900901";
        public static final String CODE = "code";
        public static final String JWT_EXP_CLAIM = "exp";
        public static final String BEARER = "Bearer ";
        public static final String BASIC = "Basic ";
        public static final int MAX_TOKEN_REQUEST_ATTEMPTS = 2;
    }
}
