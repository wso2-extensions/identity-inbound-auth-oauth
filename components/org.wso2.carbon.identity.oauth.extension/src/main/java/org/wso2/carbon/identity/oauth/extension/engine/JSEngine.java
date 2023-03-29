/*
 * Copyright (c) 2023, WSO2 LLC. (http://www.wso2.com).
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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.extension.engine;

import java.util.List;
import java.util.Map;

import javax.script.ScriptException;

/**
 * This interface is used to evaluate the javascripts.
 */
public interface JSEngine {

    JSEngine createEngine() throws ScriptException;

    JSEngine addBindings(Map<String, Object> bindings);

    JSEngine evalScript(String script) throws ScriptException;

    JSEngine invokeFunction(String functionName, Object... args) throws NoSuchMethodException, ScriptException;

    Map<String, Object> getJSObjects(List<String> bindings);
}
