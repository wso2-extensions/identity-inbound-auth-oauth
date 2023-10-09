/*
 * Copyright (c) 2023, WSO2 LLC. (https://www.wso2.com).
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

package org.wso2.carbon.identity.oauth.par.core;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.central.log.mgt.utils.LogConstants;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.util.IdentityConfigParser;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.par.common.ParConstants;
import org.wso2.carbon.identity.oauth.par.dao.ParDAOFactory;
import org.wso2.carbon.identity.oauth.par.dao.ParMgtDAO;
import org.wso2.carbon.identity.oauth.par.exceptions.ParClientException;
import org.wso2.carbon.identity.oauth.par.exceptions.ParCoreException;
import org.wso2.carbon.identity.oauth.par.model.ParAuthData;
import org.wso2.carbon.identity.oauth.par.model.ParRequestDO;
import org.wso2.carbon.utils.DiagnosticLog;

import java.util.Calendar;
import java.util.Map;
import java.util.Optional;
import java.util.TimeZone;
import java.util.UUID;

import static org.wso2.carbon.identity.oauth.common.OAuthConstants.LogConstants.InputKeys.REQUEST_URI_REF;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.PAR_EXPIRY_TIME;

/**
 * Provides PAR services.
 */
public class ParAuthServiceImpl implements ParAuthService {

    private static final Log log = LogFactory.getLog(ParAuthServiceImpl.class);
    ParMgtDAO parMgtDAO = ParDAOFactory.getInstance().getParAuthMgtDAO();

    @Override
    public ParAuthData handleParAuthRequest(Map<String, String> parameters) throws ParCoreException {

        String uuid = UUID.randomUUID().toString();

        ParAuthData parAuthResponse = new ParAuthData();
        parAuthResponse.setrequestURIReference(uuid);
        parAuthResponse.setExpiryTime(getExpiresInValue());

        persistParRequest(uuid, parameters, getScheduledExpiry(System.currentTimeMillis()));

        if (LoggerUtils.isDiagnosticLogsEnabled()) {
            DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                    OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                    OAuthConstants.LogConstants.ActionIDs.HANDLE_REQUEST);
            diagnosticLogBuilder
                    .inputParam(LogConstants.InputKeys.CLIENT_ID,
                            parameters.get(OAuthConstants.OAuth20Params.CLIENT_ID))
                    .inputParam(REQUEST_URI_REF, uuid)
                    .resultMessage("PAR auth request handled successfully.")
                    .resultStatus(DiagnosticLog.ResultStatus.SUCCESS)
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION);
            LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
        }

        return parAuthResponse;
    }

    private void persistParRequest(String uuid, Map<String, String> params, long expiresIn)
            throws ParCoreException {

        parMgtDAO.persistRequestData(uuid, params.get(OAuthConstants.OAuth20Params.CLIENT_ID),
                expiresIn, params);
    }

    @Override
    public Map<String, String> retrieveParams(String uuid, String clientId) throws ParCoreException {

        Optional<ParRequestDO> optionalParRequestDO = parMgtDAO.getRequestData(uuid);
        if (!optionalParRequestDO.isPresent()) {
            throw new ParClientException(OAuth2ErrorCodes.INVALID_REQUEST,
                    OAuthConstants.OAuthError.AuthorizationResponsei18nKey.INVALID_REQUEST_URI);
        }

        ParRequestDO parRequestDO = optionalParRequestDO.get();
        parMgtDAO.removeRequestData(uuid);
        validateExpiryTime(parRequestDO.getExpiresIn());
        validateClientID(clientId, parRequestDO.getClientId());

        if (LoggerUtils.isDiagnosticLogsEnabled()) {
            DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                    OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                    OAuthConstants.LogConstants.ActionIDs.RETRIEVE_PARAMETERS);
            diagnosticLogBuilder
                    .inputParam(LogConstants.InputKeys.CLIENT_ID, clientId)
                    .inputParam(REQUEST_URI_REF, uuid)
                    .resultMessage("PAR auth request parameters retrieved successfully.")
                    .resultStatus(DiagnosticLog.ResultStatus.SUCCESS)
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION);
            LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
        }
        return parRequestDO.getParams();
    }

    private void validateExpiryTime(long expiresIn) throws ParClientException {

        long currentTimeInMillis = Calendar.getInstance(TimeZone.getTimeZone(ParConstants.UTC)).getTimeInMillis();

        if (currentTimeInMillis > expiresIn) {
            throw new ParClientException(OAuth2ErrorCodes.INVALID_REQUEST,
                    OAuthConstants.OAuthError.AuthorizationResponsei18nKey.REQUEST_URI_EXPIRED);
        }
    }

    private void validateClientID(String clientId, String parClientId) throws ParClientException {

        if (!StringUtils.equals(parClientId, clientId)) {
            throw new ParClientException(OAuth2ErrorCodes.INVALID_REQUEST,
                    OAuthConstants.OAuthError.AuthorizationResponsei18nKey.CLIENT_IDS_NOT_MATCH);
        }
    }

    private static int getExpiresInValue() throws ParCoreException {

        try {
            String expiryTimeValue =
                    (String) IdentityConfigParser.getInstance().getConfiguration().get(PAR_EXPIRY_TIME);
            if ((StringUtils.isNotBlank(expiryTimeValue))) {
                int expiryTime = Integer.parseInt((expiryTimeValue).trim());
                if (expiryTime > 0) {
                    return expiryTime;
                }
                log.warn(String.format("PAR expiry time should be a positive integer. " +
                                "Default value: %s will be used.", ParConstants.EXPIRES_IN_DEFAULT_VALUE));
            } else {
                log.debug(String.format("PAR expiry time is not configured. Default value: %s will be used.",
                        ParConstants.EXPIRES_IN_DEFAULT_VALUE));
            }
            return ParConstants.EXPIRES_IN_DEFAULT_VALUE;

        } catch (NumberFormatException e) {
            throw new ParCoreException("Error while parsing the expiry time value.", e);
        }
    }

    private long getScheduledExpiry(long requestedTime) throws ParCoreException {

        long defaultExpiryInSecs = getExpiresInValue() * ParConstants.SEC_TO_MILLISEC_FACTOR;
        return requestedTime + defaultExpiryInSecs;
    }
}
