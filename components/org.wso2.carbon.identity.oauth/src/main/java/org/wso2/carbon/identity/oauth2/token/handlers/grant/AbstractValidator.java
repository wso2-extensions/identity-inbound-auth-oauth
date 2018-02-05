/*
 *
 *   Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *   WSO2 Inc. licenses this file to you under the Apache License,
 *   Version 2.0 (the "License"); you may not use this file except
 *   in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing,
 *   software distributed under the License is distributed on an
 *   "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *   KIND, either express or implied.  See the License for the
 *   specific language governing permissions and limitations
 *   under the License.
 *
 */

package org.wso2.carbon.identity.oauth2.token.handlers.grant;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * AbstractValidator class is extended from Apache Oltu's
 * org.apache.oltu.oauth2.common.validators.AbstractValidator AbstractValidator class and provide
 * number of additional helper methods for custom grant type Validators.
 *
 * @since 5.4.10
 */
public abstract class AbstractValidator extends org.apache.oltu.oauth2.common.validators.AbstractValidator {

	public AbstractValidator() {
		super();
		// Client Authentication is handled by
		// org.wso2.carbon.identity.oauth2.token.handlers.clientauth.ClientAuthenticationHandler extensions point.
		// Therefore client_id and client_secret are not mandatory since client can authenticate with other means.
		setEnforceClientAuthentication(false);
		configureParams();
	}

	/*
	Custom grant type Validator implementations should  implement this method to add or remove
	required, optional and not-allowed  parameters.
	 */
	abstract protected void configureParams();

	protected List<String> getRequiredParams() {
		return requiredParams;
	}

	protected void setRequiredParams(List<String> requiredParams) {
		this.requiredParams = requiredParams;
	}

	protected void addRequiredParam(String requiredParam) {
		this.requiredParams.add(requiredParam);
	}

	protected void removeRequiredParam(String requiredParam) {
		this.requiredParams.remove(requiredParam);
	}

	protected Map<String, String> getOptionalParams() {
		return optionalParams;
	}

	protected void setOptionalParams(Map<String, String> optionalParams) {
		this.optionalParams = optionalParams;
	}

	protected void addOptionalParam(String key, String optionalParam) {
		this.optionalParams.put(key, optionalParam);
	}

	protected void removeOptionalParam(String optionalParamKey) {
		this.optionalParams.remove(optionalParamKey);
	}

	protected List<String> getNotAllowedParamsParams() {
		return notAllowedParams;
	}

	protected void setNotAllowedParamsParams(List<String> params) {
		this.notAllowedParams = params == null ? new ArrayList() : params;
	}

	protected void addNotAllowedParamsParam(String param) {
		this.notAllowedParams.add(param);
	}

	protected void removeNotAllowedParamsParam(String param) {
		this.notAllowedParams.remove(param);
	}

	public boolean isEnforceClientAuthentication() {
		return enforceClientAuthentication;
	}

	public void setEnforceClientAuthentication(boolean enforceClientAuthentication) {
		this.enforceClientAuthentication = enforceClientAuthentication;
	}

}
