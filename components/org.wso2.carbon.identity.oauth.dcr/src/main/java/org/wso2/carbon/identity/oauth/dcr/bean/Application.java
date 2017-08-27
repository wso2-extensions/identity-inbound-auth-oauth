/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth.dcr.bean;

import java.io.Serializable;
import java.util.List;

public class Application implements Serializable {

    private static final long serialVersionUID = -4515815791420125411L;

    private String client_name = null;
    private String client_key = null;
    private String client_secret = null;
    private List<String> redirect_uris = null;

    public String getClient_name() {
        return client_name;
    }

    public void setClient_name(String clientName) {
        this.client_name = clientName;
    }

    public String getClient_key() {
        return client_key;
    }

    public void setClient_key(String client_key) {
        this.client_key = client_key;
    }

    public String getClient_secret() {
        return client_secret;
    }

    public void setClient_secret(String client_secret) {
        this.client_secret = client_secret;
    }


    public List<String> getRedirect_uris() {
        return redirect_uris;
    }

    public void setRedirect_uris(List<String> redirect_uris) {
        this.redirect_uris = redirect_uris;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("Application {\n");
        sb.append("  client_name: ").append(this.client_name).append("\n");
        sb.append("  client_id: ").append(this.client_key).append("\n");
        sb.append("  client_secret: ").append(this.client_secret).append("\n");
        sb.append("  redirect_uris: ").append(this.redirect_uris).append("\n");
        sb.append("}\n");
        return sb.toString();
    }
}
