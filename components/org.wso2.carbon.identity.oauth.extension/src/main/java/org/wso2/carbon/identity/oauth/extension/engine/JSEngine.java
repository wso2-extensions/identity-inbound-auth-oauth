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
 * An interface representing a JavaScript engine that can execute and evaluate JavaScript code.
 */
public interface JSEngine {

    /**
     * Creates a new instance of the JavaScript engine.
     *
     * @return The new JavaScript engine instance.
     * @throws ScriptException If an error occurs while creating the engine.
     */
    JSEngine createEngine() throws ScriptException;

    /**
     * Adds the specified bindings to the JavaScript engine.
     *
     * @param bindings A map of key-value pairs representing the bindings to add.
     * @return This JavaScript engine instance, with the specified bindings added.
     */
    JSEngine addBindings(Map<String, Object> bindings);

    /**
     * Evaluates the specified JavaScript code in the JavaScript engine.
     *
     * @param script The JavaScript code to evaluate.
     * @return This JavaScript engine instance, after evaluating the code.
     * @throws ScriptException If an error occurs while evaluating the code.
     */
    JSEngine evalScript(String script) throws ScriptException;

    /**
     * Invokes the specified function in the JavaScript engine with the specified arguments.
     *
     * @param functionName The name of the function to invoke.
     * @param args         The arguments to pass to the function.
     * @return This JavaScript engine instance, after invoking the function.
     * @throws NoSuchMethodException If the specified function does not exist.
     * @throws ScriptException       If an error occurs while invoking the function.
     */
    JSEngine invokeFunction(String functionName, Object... args) throws NoSuchMethodException, ScriptException;

    /**
     * Returns a map of JavaScript objects from the specified list of bindings.
     *
     * @param bindings A list of binding names to retrieve.
     * @return A map of key-value pairs representing the JavaScript objects from the specified bindings.
     */
    Map<String, Object> getJSObjects(List<String> bindings);
}
