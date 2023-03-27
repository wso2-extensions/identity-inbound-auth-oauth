package org.wso2.carbon.identity.oauth.extension.engine.impl;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.openjdk.nashorn.api.scripting.NashornScriptEngineFactory;
import org.openjdk.nashorn.api.scripting.ScriptObjectMirror;
import org.wso2.carbon.identity.oauth.extension.engine.JSEngine;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.script.Bindings;
import javax.script.Invocable;
import javax.script.ScriptContext;
import javax.script.ScriptEngine;
import javax.script.ScriptException;

/**
 * This class is used to evaluate the javascripts using openjdk nashorn.
 */
public class OpenJdkJSEngineImpl implements JSEngine {

    private final ScriptEngine engine;
    public static final String[] NASHORN_ARGS = {"--no-java"};
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
    private static final JSEngine OPEN_JDK_JS_ENGINE_INSTANCE = new OpenJdkJSEngineImpl();
    private static final Log log = LogFactory.getLog(OpenJdkJSEngineImpl.class);

    public OpenJdkJSEngineImpl() {

        NashornScriptEngineFactory factory = new NashornScriptEngineFactory();
        this.engine = factory.getScriptEngine(NASHORN_ARGS);
    }

    /**
     * Returns an instance to log the javascript errors.
     *
     * @return jsBasedEngineInstance instance.
     */
    public static JSEngine getInstance() {

        return OPEN_JDK_JS_ENGINE_INSTANCE;
    }

    @Override
    public JSEngine createEngine() throws ScriptException {

        Bindings bindings = engine.createBindings();
        engine.setBindings(bindings, ScriptContext.GLOBAL_SCOPE);
        engine.setBindings(engine.createBindings(), ScriptContext.ENGINE_SCOPE);
        engine.eval(REMOVE_FUNCTIONS);
        return OPEN_JDK_JS_ENGINE_INSTANCE;
    }

    @Override
    public ScriptEngine getEngine() throws ScriptException {

        return engine;
    }

    @Override
    public JSEngine addBindings(Map<String, Object> bindings) {

        engine.getBindings(javax.script.ScriptContext.ENGINE_SCOPE).putAll(bindings);
        return OPEN_JDK_JS_ENGINE_INSTANCE;
    }

    @Override
    public JSEngine evalScript(String script) throws ScriptException {

        engine.eval(script);
        return OPEN_JDK_JS_ENGINE_INSTANCE;
    }

    @Override
    public JSEngine invokeFunction(String functionName, Object... args) throws ScriptException, NoSuchMethodException {

        Object scriptObj = engine.get(functionName);
        if (scriptObj != null && ((ScriptObjectMirror) scriptObj).isFunction()) {
            Invocable invocable = (Invocable) engine;
            invocable.invokeFunction(functionName, args);
            return OPEN_JDK_JS_ENGINE_INSTANCE;
        }
        log.warn("Function " + functionName + " is not defined in the script.");
        return OPEN_JDK_JS_ENGINE_INSTANCE;
    }

    @Override
    public Map<String, Object> getJSObjects(List<String> objectNames) {

        Map<String, Object> jsObjects = new HashMap<>();
        for (String objectName : objectNames) {
            if (engine.get(objectName) != null) {
                jsObjects.put(objectName, engine.get(objectName));
            }
        }
        return jsObjects;
    }
}
