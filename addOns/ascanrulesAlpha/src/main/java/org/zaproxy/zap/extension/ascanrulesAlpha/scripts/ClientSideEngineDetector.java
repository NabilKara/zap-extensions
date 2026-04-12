package org.zaproxy.zap.extension.ascanrulesAlpha.scripts;

import java.util.LinkedHashMap;
import java.util.Map;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.openqa.selenium.JavascriptExecutor;
import org.openqa.selenium.WebDriver;

public class ClientSideEngineDetector {

    private static final Logger LOGGER = LogManager.getLogger(ClientSideEngineDetector.class);

    static final Map<String, String> TEMPLATES = new LinkedHashMap<>();

    static {
        TEMPLATES.put("angular",        "angular.version");
        TEMPLATES.put("vue",            "Vue");
        TEMPLATES.put("mavo",           "Mavo");
        TEMPLATES.put("handlebars",     "Handlebars");
        TEMPLATES.put("regular",        "Regular");
        TEMPLATES.put("template7",      "Template7");
        TEMPLATES.put("ejs",            "ejs");
        TEMPLATES.put("marko",          "Marko");
        TEMPLATES.put("tmpl",           "$.tmpl");
        TEMPLATES.put("ember",          "Ember");
        TEMPLATES.put("jsrender",       "jsrender");
        TEMPLATES.put("dot",            "doT");
        TEMPLATES.put("art-template",   "template");
        TEMPLATES.put("tempo",          "Tempo");
        TEMPLATES.put("transparency",   "Transparency");
        TEMPLATES.put("svelte",         "__svelte");
        TEMPLATES.put("underscore",     "_.template");
        TEMPLATES.put("lit",            "litHtmlVersions");
        TEMPLATES.put("mustache",       "Mustache");
        TEMPLATES.put("hogan",          "Hogan");
        TEMPLATES.put("twig",           "Twig");
        TEMPLATES.put("markup",         "Markup");
        TEMPLATES.put("dust",           "dust");
        TEMPLATES.put("nunjucks",       "nunjucks");
        TEMPLATES.put("pug",            "pug");
        TEMPLATES.put("loadTemplate",   "loadTemplate");
        TEMPLATES.put("pure",           "$p");
        TEMPLATES.put("squirrelly",     "Sqrl");
        TEMPLATES.put("swig",           "swig");
        TEMPLATES.put("icanhaz",        "ich");
        TEMPLATES.put("micro-template", "template");
        TEMPLATES.put("juicer",         "Juicer");
        TEMPLATES.put("alpine",         "Alpine");
    }


    private static final String PAYLOAD =
            "try {" +
                    "  var parts = String(arguments[0]).split('.');" +
                    "  var obj = window;" +
                    "  for (var i = 0; i < parts.length; i++) {" +
                    "    if (obj == null || obj === undefined) return false;" +
                    "    obj = obj[parts[i]];" +
                    "  }" +
                    "  return obj !== undefined && obj !== null;" +
                    "} catch (e) { return false; }";

    public record DetectionResult(String engineName, String globalExpression) {
        public boolean detected() {
            return !"unknown".equals(engineName);
        }

        @Override
        public String toString() {
            if (!detected()) return "engine=unknown";
            return String.format("engine=%-15s  global=%s", engineName, globalExpression);
        }
    }

    public static DetectionResult detect(WebDriver driver, String url) {
        if (driver == null) return unknown();

        try {
            driver.get(url);
            Thread.sleep(1500);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            LOGGER.warn("CSTI: engine detection interrupted for {}", url);
            return unknown();
        } catch (Exception e) {
            LOGGER.warn(
                    "CSTI: failed to load '{}' for engine detection ({}): {}",
                    url,
                    e.getClass().getSimpleName(),
                    e.getMessage());
            return unknown();
        }

        JavascriptExecutor js = (JavascriptExecutor) driver;

        for (Map.Entry<String, String> entry : TEMPLATES.entrySet()) {
            String engine = entry.getKey();
            String global = entry.getValue();
            try {
                if (evalExpr(js, global)) {
                    LOGGER.info("CSTI: engine '{}' detected via global '{}'", engine, global);
                    return new DetectionResult(engine, global);
                }
            } catch (Exception e) {
                // Ignore per-engine probe errors and continue with remaining probes.
            }
        }

        LOGGER.warn("CSTI: no engine detected for {}", url);
        return unknown();
    }
    private static boolean evalExpr(JavascriptExecutor js, String global) {
        Object result = js.executeScript(PAYLOAD, global);
        return Boolean.TRUE.equals(result);
    }

    private static DetectionResult unknown() {
        return new DetectionResult("unknown", "");
    }
}