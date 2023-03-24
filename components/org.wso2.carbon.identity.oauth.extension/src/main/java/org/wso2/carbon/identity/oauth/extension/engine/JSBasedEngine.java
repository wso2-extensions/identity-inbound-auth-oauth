package org.wso2.carbon.identity.oauth.extension.engine;

import java.util.List;
import java.util.Map;

import javax.script.ScriptEngine;
import javax.script.ScriptException;

public interface JSBasedEngine {

    JSBasedEngine createEngine() throws ScriptException;

    ScriptEngine getEngine() throws ScriptException;

    JSBasedEngine addBindings(Map<String, Object> bindings);

    JSBasedEngine evalScript(String script) throws ScriptException;

    JSBasedEngine invokeFunction(String functionName, Object... args) throws ScriptException, NoSuchMethodException;

    Map<String, Object> getJSObjects(List<String> bindings);
}
