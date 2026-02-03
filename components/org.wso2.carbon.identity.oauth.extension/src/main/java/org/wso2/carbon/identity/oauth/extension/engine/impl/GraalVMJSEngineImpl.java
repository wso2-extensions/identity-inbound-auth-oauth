/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 *  
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.extension.engine.impl;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.graalvm.polyglot.Context;
import org.graalvm.polyglot.EnvironmentAccess;
import org.graalvm.polyglot.HostAccess;
import org.graalvm.polyglot.Value;
import org.wso2.carbon.identity.oauth.extension.engine.JSEngine;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.script.ScriptException;

/**
 * This class is used to evaluate JavaScript code using GraalVM's Polyglot API.
 */
public class GraalVMJSEngineImpl implements JSEngine {

    private Context context;
    private static final String REMOVE_FUNCTIONS = "var quit=function(){Log.error('quit function is restricted.')};" +
            "var exit=function(){Log.error('exit function is restricted.')};" +
            "var print=function(){Log.error('print function is restricted.')};" +
            "var echo=function(){Log.error('echo function is restricted.')};" +
            "var readFully=function(){Log.error('readFully function is restricted.')};" +
            "var readLine=function(){Log.error('readLine function is restricted.')};" +
            "var load=function(){Log.error('load function is restricted.')};" +
            "var loadWithNewGlobal=function(){Log.error('loadWithNewGlobal function is restricted.')};" +
            "var $ARG=null;var $ENV=null;var $EXEC=null;" +
            "var $OPTIONS=null;var $OUT=null;var $ERR=null;var $EXIT=null;" +
            "Object.defineProperty(this, 'engine', {});";
    private static final JSEngine GRAAL_VM_JS_ENGINE_INSTANCE = new GraalVMJSEngineImpl();
    private static final Log log = LogFactory.getLog(GraalVMJSEngineImpl.class);
    private static final String JS_LANGUAGE = "js";

    public GraalVMJSEngineImpl() {

        // Changed HostAccess from NONE -> ALL so JS scripts can call public methods on bound Java objects (e.g., Log.info).
        // This is safe because scripts are written by trusted parties;
        this.context = Context.newBuilder(JS_LANGUAGE)
                .allowHostAccess(HostAccess.ALL)
                .allowHostClassLookup(className -> false)
                .allowIO(false)
                .allowCreateThread(false)
                .allowNativeAccess(false)
                .allowCreateProcess(false)
                .allowEnvironmentAccess(EnvironmentAccess.NONE)
                .allowExperimentalOptions(false)
                .build();
    }

    /**
     * Returns an instance to log the JavaScript errors.
     *
     * @return GraalVM JS engine instance.
     */
    public static JSEngine getInstance() {

        return GRAAL_VM_JS_ENGINE_INSTANCE;
    }

    @Override
    public JSEngine createEngine() throws ScriptException {

        try {
            // Close existing context if any
            if (context != null) {
                context.close();
            }
            // Create a new isolated context
            this.context = Context.newBuilder(JS_LANGUAGE)
                    .allowHostAccess(HostAccess.ALL)
                    .allowHostClassLookup(className -> false)
                    .allowIO(false)
                    .allowCreateThread(false)
                    .allowNativeAccess(false)
                    .allowCreateProcess(false)
                    .allowEnvironmentAccess(EnvironmentAccess.NONE)
                    .allowExperimentalOptions(false)
                    .build();
            // Remove restricted functions
            context.eval(JS_LANGUAGE, REMOVE_FUNCTIONS);
            return GRAAL_VM_JS_ENGINE_INSTANCE;
        } catch (Exception e) {
            throw new ScriptException("Error creating GraalVM JavaScript engine: " + e.getMessage());
        }
    }

    @Override
    public JSEngine addBindings(Map<String, Object> bindings) {

        if (context != null && bindings != null) {
            Value jsBindings = context.getBindings(JS_LANGUAGE);
            for (Map.Entry<String, Object> entry : bindings.entrySet()) {
                jsBindings.putMember(entry.getKey(), entry.getValue());
            }
        }
        return GRAAL_VM_JS_ENGINE_INSTANCE;
    }

    @Override
    public JSEngine evalScript(String script) throws ScriptException {

        try {
            if (context != null && script != null && !script.isEmpty()) {
                context.eval(JS_LANGUAGE, script);
            }
            return GRAAL_VM_JS_ENGINE_INSTANCE;
        } catch (Exception e) {
            throw new ScriptException("Error evaluating JavaScript: " + e.getMessage());
        }
    }

    @Override
    public JSEngine invokeFunction(String functionName, Object... args) throws NoSuchMethodException, ScriptException {

        try {
            if (context == null) {
                throw new ScriptException("Context is not initialized");
            }
            
            Value jsBindings = context.getBindings(JS_LANGUAGE);
            Value function = jsBindings.getMember(functionName);
            
            if (function == null || !function.canExecute()) {
                log.warn(String.format("Function %s is not defined in the script.", functionName));
                return GRAAL_VM_JS_ENGINE_INSTANCE;
            }
            
            function.execute(args);
            return GRAAL_VM_JS_ENGINE_INSTANCE;
        } catch (Exception e) {
            if (e.getMessage() != null && e.getMessage().contains("not defined")) {
                throw new NoSuchMethodException("Function " + functionName + " is not defined");
            }
            throw new ScriptException("Error invoking function " + functionName + ": " + e.getMessage());
        }
    }

    @Override
    public Map<String, Object> getJSObjects(List<String> objectNames) {

        Map<String, Object> jsObjects = new HashMap<>();
        if (context != null && objectNames != null) {
            Value jsBindings = context.getBindings(JS_LANGUAGE);
            for (String objectName : objectNames) {
                Value member = jsBindings.getMember(objectName);
                if (member != null && !member.isNull()) {
                    // Convert GraalVM Value to appropriate Java object
                    jsObjects.put(objectName, convertValueToJavaObject(member));
                }
            }
        }
        return jsObjects;
    }

    /**
     * Converts a GraalVM Value to an appropriate Java object.
     *
     * @param value The GraalVM Value to convert.
     * @return The converted Java object.
     */
    private Object convertValueToJavaObject(Value value) {

        if (value.isNull()) {
            return null;
        } else if (value.isBoolean()) {
            return value.asBoolean();
        } else if (value.isNumber()) {
            if (value.fitsInInt()) {
                return value.asInt();
            } else if (value.fitsInLong()) {
                return value.asLong();
            } else if (value.fitsInDouble()) {
                return value.asDouble();
            }
        } else if (value.isString()) {
            return value.asString();
        } else if (value.hasArrayElements()) {
            long size = value.getArraySize();
            Object[] array = new Object[(int) size];
            for (int i = 0; i < size; i++) {
                array[i] = convertValueToJavaObject(value.getArrayElement(i));
            }
            return array;
        } else if (value.hasMembers()) {
            Map<String, Object> map = new HashMap<>();
            for (String key : value.getMemberKeys()) {
                map.put(key, convertValueToJavaObject(value.getMember(key)));
            }
            return map;
        }
        // Return the Value itself if no conversion is applicable
        return value;
    }

    /**
     * Closes the GraalVM context and releases resources.
     */
    public void close() {

        if (context != null) {
            context.close();
            context = null;
        }
    }
}
