package org.wso2.carbon.identity.oauth.extension.functions;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.reflect.TypeToken;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.concurrent.FutureCallback;
import org.apache.http.conn.ConnectTimeoutException;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.apache.http.impl.nio.client.CloseableHttpAsyncClient;
import org.apache.http.impl.nio.client.HttpAsyncClients;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Type;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;

import static org.apache.http.HttpHeaders.ACCEPT;
import static org.apache.http.HttpHeaders.CONTENT_TYPE;
import static org.wso2.carbon.identity.oauth.extension.Utils.Constants.CallChoreoConstants.ACCESS_TOKEN_KEY;
import static org.wso2.carbon.identity.oauth.extension.Utils.Constants.CallChoreoConstants.AUTHORIZATION;
import static org.wso2.carbon.identity.oauth.extension.Utils.Constants.CallChoreoConstants.BASIC;
import static org.wso2.carbon.identity.oauth.extension.Utils.Constants.CallChoreoConstants.BEARER;
import static org.wso2.carbon.identity.oauth.extension.Utils.Constants.CallChoreoConstants.CODE;
import static org.wso2.carbon.identity.oauth.extension.Utils.Constants.CallChoreoConstants.CONSUMER_SECRET_VARIABLE_NAME;
import static org.wso2.carbon.identity.oauth.extension.Utils.Constants.CallChoreoConstants.ERROR_CODE_ACCESS_TOKEN_INACTIVE;
import static org.wso2.carbon.identity.oauth.extension.Utils.Constants.CallChoreoConstants.GRANT_TYPE;
import static org.wso2.carbon.identity.oauth.extension.Utils.Constants.CallChoreoConstants.GRANT_TYPE_CLIENT_CREDENTIALS;
import static org.wso2.carbon.identity.oauth.extension.Utils.Constants.CallChoreoConstants.HTTP_STATUS_OK;
import static org.wso2.carbon.identity.oauth.extension.Utils.Constants.CallChoreoConstants.HTTP_STATUS_UNAUTHORIZED;
import static org.wso2.carbon.identity.oauth.extension.Utils.Constants.CallChoreoConstants.MAX_TOKEN_REQUEST_ATTEMPTS;
import static org.wso2.carbon.identity.oauth.extension.Utils.Constants.CallChoreoConstants.TYPE_APPLICATION_JSON;
import static org.wso2.carbon.identity.oauth.extension.Utils.Constants.CallChoreoConstants.TYPE_FORM_DATA;
import static org.wso2.carbon.identity.oauth.extension.Utils.Constants.OUTCOME_FAIL;
import static org.wso2.carbon.identity.oauth.extension.Utils.Constants.OUTCOME_SUCCESS;
import static org.wso2.carbon.identity.oauth.extension.Utils.Constants.OUTCOME_TIMEOUT;

public class CallChoreoFunctionImpl implements CallChoreoFunction {

    private static final String URL_VARIABLE_NAME = "url";
    private static final String CONSUMER_KEY_VARIABLE_NAME = "consumerKey";
    private static final String CONSUMER_KEY_ALIAS_VARIABLE_NAME = "consumerKeyAlias";
    private final List<String> choreoDomains;
//    private final ChoreoAccessTokenCache choreoAccessTokenCache;
    private static final Log LOG = LogFactory.getLog(CallChoreoFunctionImpl.class);
    private final String tenantDomain;
    private final Callback callback;
    public CallChoreoFunctionImpl(String tenantDomain, Callback callback) {

        this.choreoDomains = new ArrayList<>();
        this.callback = callback;
//        this.choreoAccessTokenCache = ChoreoAccessTokenCache.getInstance();
        this.tenantDomain = tenantDomain;
    }

    @Override
    public void callChoreo(Map<String, String> connectionMetaData, Map<String, Object> payloadData,
                           Map<String, Object> eventHandlers) {

        String epUrl = connectionMetaData.get(URL_VARIABLE_NAME);
        try {
//            if (!CallChoreoUtils.isValidChoreoDomain(epUrl,choreoDomains)) {
//                LOG.error("Provided Url does not contain a configured choreo domain. Invalid Url: " + epUrl);
//                return;
//            }

            AccessTokenRequestHelper accessTokenRequestHelper = new AccessTokenRequestHelper(
                    connectionMetaData, payloadData, eventHandlers);
            String accessToken = null;
//                    choreoAccessTokenCache.getValueFromCache(accessTokenRequestHelper.getConsumerKey(),
//                    tenantDomain);
//            if (StringUtils.isNotEmpty(accessToken) && !CallChoreoUtils.isTokenExpired(accessToken)) {
            if (StringUtils.isNotEmpty(accessToken)) {
                accessTokenRequestHelper.callChoreoEndpoint(accessToken);
            } else {
                LOG.debug("Requesting the access token from Choreo");
                accessToken = requestAccessToken(tenantDomain, accessTokenRequestHelper);
                accessTokenRequestHelper.callChoreoEndpoint(accessToken);
            }
        } catch (IllegalArgumentException e) {
            LOG.error("Invalid endpoint Url: " + epUrl, e);
            callback.accept(eventHandlers, Collections.emptyMap(), OUTCOME_FAIL);
        } catch (IOException e) {
            LOG.error("Error while requesting access token from Choreo.", e);
            callback.accept(eventHandlers, Collections.emptyMap(), OUTCOME_FAIL);
//        } catch (SecretManagementClientException e) {
//            LOG.debug("Client error while resolving Choreo consumer key or secret.", e);
//            Callback.accept(eventHandlers, Collections.emptyMap(), OUTCOME_FAIL);
//        } catch (SecretManagementException e) {
//            LOG.error("Error while resolving Choreo consumer key or secret.", e);
//            Callback.accept(eventHandlers, Collections.emptyMap(), OUTCOME_FAIL);
        } catch (Exception e) {
            LOG.error("Error while invoking callChoreo.", e);
            callback.accept(eventHandlers, Collections.emptyMap(), OUTCOME_FAIL);
        }
    }

    /**
     * Performs the access token request using client credentials grant type.
     *
     * @param tenantDomain             The tenant domain which the request belongs to.
     * @param accessTokenRequestHelper The future callback that needs to be called after requesting the token.
     * @return
     * @throws IOException        {@link IOException}
     * @throws FrameworkException {@link FrameworkException}
     */
    private String requestAccessToken(String tenantDomain, AccessTokenRequestHelper accessTokenRequestHelper)
            throws IOException {

        RequestConfig requestConfig = RequestConfig.custom()
                .setConnectTimeout(1000) // 5 seconds timeout for connection
                .setSocketTimeout(1000) // 5 seconds timeout for waiting for data
                .build();
        HttpPost request = new HttpPost("https://sts.choreo.dev/oauth2/token");
        request.setHeader(ACCEPT, TYPE_APPLICATION_JSON);
        request.setHeader(CONTENT_TYPE, TYPE_FORM_DATA);
        request.setConfig(requestConfig);
        request.setHeader(AUTHORIZATION, BASIC + Base64.getEncoder()
                .encodeToString((accessTokenRequestHelper.consumerKey + ":" + accessTokenRequestHelper.consumerSecret)
                        .getBytes(StandardCharsets.UTF_8)));

        List<BasicNameValuePair> bodyParams = new ArrayList<>();
        bodyParams.add(new BasicNameValuePair(GRANT_TYPE, GRANT_TYPE_CLIENT_CREDENTIALS));
        request.setEntity(new UrlEncodedFormEntity(bodyParams));
        HttpClient httpClient = HttpClientBuilder.create().build();
        HttpResponse response = httpClient.execute(request);
        String responseString = EntityUtils.toString(response.getEntity());
        JsonObject jsonObject = JsonParser.parseString(responseString).getAsJsonObject();
        String accessToken = jsonObject.get("access_token").toString().replaceAll("\"", "");
        return accessToken;
    }

    private class AccessTokenRequestHelper implements FutureCallback<HttpResponse> {

        private final Map<String, String> connectionMetaData;
        private final Map<String, Object> payloadData;
        private final Gson gson;
        private final AtomicInteger tokenRequestAttemptCount;
        private String consumerKey;
        private String consumerSecret;
        private Map<String, Object> eventHandlers;

        public AccessTokenRequestHelper(Map<String, String> connectionMetaData,
                                        Map<String, Object> payloadData, Map<String, Object> eventHandlers) {

            this.connectionMetaData = connectionMetaData;
            this.payloadData = payloadData;
            this.gson = new GsonBuilder().create();
            this.tokenRequestAttemptCount = new AtomicInteger(0);
            this.eventHandlers = eventHandlers;
            resolveConsumerKeySecrete();
        }

        /**
         * The method to be called when access token request receives an HTTP response.
         *
         * @param httpResponse Received HTTP response.
         */
        @Override
        public void completed(HttpResponse httpResponse) {

            boolean isFailure = false;
            try {
                LOG.debug("Access token response received.");
                int responseCode = httpResponse.getStatusLine().getStatusCode();
                if (responseCode == HTTP_STATUS_OK) {
                    Type responseBodyType = new TypeToken<Map<String, String>>() { }.getType();
                    Map<String, String> responseBody = this.gson
                            .fromJson(EntityUtils.toString(httpResponse.getEntity()), responseBodyType);
                    String accessToken = responseBody.get(ACCESS_TOKEN_KEY);
                    if (accessToken != null) {
//                        choreoAccessTokenCache.addToCache(this.consumerKey, accessToken, tenantDomain);
                        callChoreoEndpoint(accessToken);
                    } else {
                        LOG.error("Token response does not contain an access token.");
                        isFailure = true;
                    }
                } else {
                    LOG.error("Failed to retrieve access token from Choreo.");
                    isFailure = true;
                }
            } catch (IOException e) {
                LOG.error("Failed to parse access token response to string.", e);
                isFailure = true;
            } catch (Exception e) {
                LOG.error("Error occurred while handling the token response from Choreo.", e);
                isFailure = true;
            }

            if (isFailure) {
                try {
                    return;
//                    asyncReturn.accept(authenticationContext, Collections.emptyMap(), OUTCOME_FAIL);
                } catch (Exception e) {
                    LOG.error("Error while trying to return after handling the token request failure from Choreo.", e);
                }
            }
        }

        /**
         * The method to be called when access token request fails.
         *
         * @param e Thrown exception.
         */
        @Override
        public void failed(Exception e) {

            LOG.error("Failed to request access token from Choreo", e);
            try {
                String outcome = OUTCOME_FAIL;
                if ((e instanceof SocketTimeoutException) || (e instanceof ConnectTimeoutException)) {
                    outcome = OUTCOME_TIMEOUT;
                }
                callback.accept(eventHandlers, Collections.emptyMap(), OUTCOME_FAIL);
            } catch (Exception ex) {
                LOG.error("Error while proceeding after failing to request access token", e);
            }
        }

        /**
         * The method to be called when access token request canceled.
         */
        @Override
        public void cancelled() {

            LOG.error("Requesting access token from Choreo is cancelled.");
            try {
                callback.accept(eventHandlers, Collections.emptyMap(), OUTCOME_FAIL);
            } catch (Exception e) {
                LOG.error("Error while proceeding after access token request to Choreo got cancelled", e);
            }
        }

        /**
         * Invokes the Choreo API endpoint specified in the connection metadata using the provided access token.
         *
         * @param accessToken Access token that authorizes the request.
         */
        private void callChoreoEndpoint(String accessToken) {

            boolean isFailure = false;
            HttpPost request = new HttpPost(this.connectionMetaData.get(URL_VARIABLE_NAME));
            request.setHeader(ACCEPT, TYPE_APPLICATION_JSON);
            request.setHeader(CONTENT_TYPE, TYPE_APPLICATION_JSON);
            request.setHeader(AUTHORIZATION, BEARER + accessToken);

            try {
                Gson gson = new Gson();
                String payloadJson = gson.toJson(this.payloadData);
                request.setEntity(new StringEntity(payloadJson));
                RequestConfig requestConfig = RequestConfig.custom()
                        .setSocketTimeout(5)
                        .setConnectTimeout(5)
                        .build();
                CloseableHttpAsyncClient client = HttpAsyncClients.custom()
                        .setDefaultRequestConfig(requestConfig)
                        .build();
                client.start();
                CountDownLatch latch = new CountDownLatch(1);
                client.execute(request, new FutureCallback<HttpResponse>() {

                    @Override
                    public void completed(final HttpResponse response) {

                        try {
                            handleChoreoEndpointResponse(response);
                        } catch (Exception e) {
                            LOG.error("Error while proceeding after handling the response from Choreo" , e);
                        } finally {
                            latch.countDown();
                        }
                    }

                    @Override
                    public void failed(final Exception ex) {

                        LOG.error("Failed to invoke Choreo", ex);
                        try {
                            String outcome = OUTCOME_FAIL;
                            if ((ex instanceof SocketTimeoutException) || (ex instanceof ConnectTimeoutException)) {
                                outcome = OUTCOME_TIMEOUT;
                            }
                            callback.accept(eventHandlers, Collections.emptyMap(), OUTCOME_FAIL);
                        } catch (Exception e) {
                            LOG.error("Error while proceeding after failed response from Choreo " +
                                    "call for session data key: ", e);
                        } finally {
                            latch.countDown();
                        }
                    }

                    @Override
                    public void cancelled() {

                        LOG.error("Invocation Choreo for session data key: is cancelled.");
                        try {
                            callback.accept(eventHandlers, Collections.emptyMap(), OUTCOME_FAIL);
                        } catch (Exception e) {
                            LOG.error("Error while proceeding after cancelled response from Choreo call for session " +
                                    "data key: ", e);
                        } finally {
                            latch.countDown();
                        }
                    }
                });
                latch.await();
            } catch (UnsupportedEncodingException e) {
                LOG.error("Error while constructing request payload for calling choreo endpoint. session data key: " , e);
                isFailure = true;
            } catch (Exception e) {
                LOG.error("Error while calling Choreo endpoint. session data key: ", e);
                isFailure = true;
            }

            if (isFailure) {
                try {
                    callback.accept(eventHandlers, Collections.emptyMap(), OUTCOME_FAIL);
                } catch (Exception e) {
                    LOG.error("Error while trying to return from Choreo call after an exception", e);
                }
            }
        }

        /**
         * Handles the response from the API call to the Choreo endpoint specified in the connection metadata.
         *
         * @param response HTTP response from the Choreo endpoint.
         * @throws FrameworkException {@link FrameworkException}
         */
        private void handleChoreoEndpointResponse(final HttpResponse response) throws FrameworkException {

            Type responseBodyType;
            try {
                int statusCode = response.getStatusLine().getStatusCode();
                if (statusCode == HTTP_STATUS_OK) {
                    responseBodyType = new TypeToken<Map<String, Object>>() { }.getType();
                    Map<String, Object> successResponseBody = this.gson
                            .fromJson(EntityUtils.toString(response.getEntity()), responseBodyType);
                    callback.accept(eventHandlers, successResponseBody, OUTCOME_SUCCESS);
                } else if (statusCode == HTTP_STATUS_UNAUTHORIZED) {
                    responseBodyType = new TypeToken<Map<String, String>>() { }.getType();
                    Map<String, String> responseBody = this.gson
                            .fromJson(EntityUtils.toString(response.getEntity()), responseBodyType);

                    if (ERROR_CODE_ACCESS_TOKEN_INACTIVE.equals(responseBody.get(CODE))) {
                        handleExpiredToken();
                    } else {
                        LOG.warn("Received 401 response from Choreo. Session data key: ");
                        callback.accept(eventHandlers, Collections.emptyMap(), OUTCOME_FAIL);
                    }
                } else {
                    LOG.warn("Received non 200 response code from Choreo. Status Code: " + statusCode);
                    callback.accept(eventHandlers, Collections.emptyMap(), OUTCOME_FAIL);
                }
            } catch (IOException e) {
                LOG.error("Error while reading response from Choreo call for session data key: ", e);
                callback.accept(eventHandlers, Collections.emptyMap(), OUTCOME_FAIL);
            } catch (Exception e) {
                LOG.error("Error while processing response from Choreo call for session data key: ", e);
                callback.accept(eventHandlers, Collections.emptyMap(), OUTCOME_FAIL);
            }
        }

        /**
         * Handles the scenario where the response from the Choreo API call is 401 Unauthorized due to an expired
         * token. The program will retry the token request flow until it exceeds the specified max request attempt
         * count.
         *
         * @throws IOException {@link IOException}
         */
        private void handleExpiredToken() throws IOException {

            if (tokenRequestAttemptCount.get() < MAX_TOKEN_REQUEST_ATTEMPTS) {
                requestAccessToken(tenantDomain, this);
                tokenRequestAttemptCount.incrementAndGet();
            } else {
                LOG.warn("Maximum token request attempt count exceeded for session data key: ");
                tokenRequestAttemptCount.set(0);
                callback.accept(eventHandlers, Collections.emptyMap(), OUTCOME_FAIL);
            }
        }

        public void resolveConsumerKeySecrete() {

            this.consumerKey = connectionMetaData.get(CONSUMER_KEY_VARIABLE_NAME);
            this.consumerSecret = connectionMetaData.get(CONSUMER_SECRET_VARIABLE_NAME);
//            if (StringUtils.isNotEmpty(connectionMetaData.get(CONSUMER_KEY_VARIABLE_NAME))) {
//                this.consumerKey = connectionMetaData.get(CONSUMER_KEY_VARIABLE_NAME);
//            } else {
//                String consumerKeyAlias = connectionMetaData.get(CONSUMER_KEY_ALIAS_VARIABLE_NAME);
//                this.consumerKey = org.wso2.carbon.identity.conditional.auth.functions.choreo.CallChoreoFunctionImpl.getResolvedSecret(consumerKeyAlias);
//            }
//
//            if (StringUtils.isNotEmpty(connectionMetaData.get(CONSUMER_SECRET_VARIABLE_NAME))) {
//                this.consumerSecret = connectionMetaData.get(CONSUMER_SECRET_VARIABLE_NAME);
//            } else {
//                String consumerSecretAlias = connectionMetaData.get(CONSUMER_SECRET_ALIAS_VARIABLE_NAME);
//                this.consumerSecret = CallChoreoFunctionImpl.getResolvedSecret(consumerSecretAlias);
//            }
        }

        public void setConsumerKey(String consumerKey) {

            this.consumerKey = consumerKey;
        }

        public String getConsumerKey() {

            return consumerKey;
        }

        public String getConsumerSecret() {

            return consumerSecret;
        }

        public void setConsumerSecret(String consumerSecret) {

            this.consumerSecret = consumerSecret;
        }
    }
}
