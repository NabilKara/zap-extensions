package org.zaproxy.zap.extension.ascanrulesAlpha;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import lombok.AccessLevel;
import lombok.Setter;
import org.apache.commons.configuration.ConversionException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.openqa.selenium.WebDriver;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.AbstractAppPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.addon.client.ExtensionClientIntegration;
import org.zaproxy.addon.client.internal.ClientNode;
import org.zaproxy.addon.client.internal.ClientSideComponent;
import org.zaproxy.addon.client.internal.ClientSideDetails;
import org.zaproxy.zap.extension.selenium.Browser;
import org.zaproxy.zap.extension.selenium.ExtensionSelenium;
import org.zaproxy.zap.extension.ascanrulesAlpha.scripts.ClientSideEngineDetector;

public class CstiActiveScanRule extends AbstractAppPlugin {

    enum EngineConfidence {
        LOW,
        HIGH,
        VERY_HIGH
    }

    private static final Logger LOGGER = LogManager.getLogger(CstiActiveScanRule.class);
    private static final int PLUGIN_ID = 553542;
    private static final String MESSAGE_PREFIX = "ascanalpha.csti.";
    private static final String RULE_BROWSER_ID = "rules.ascanalpha.csti.browserid";
    private static final Browser DEFAULT_BROWSER = Browser.FIREFOX_HEADLESS;


    private static final AtomicReference<WebDriver> sharedDriver = new AtomicReference<>(null);
    private static final java.util.concurrent.locks.ReentrantLock browserLock =
            new java.util.concurrent.locks.ReentrantLock();


    private static final Set<String> scannedKeys = ConcurrentHashMap.newKeySet();

    private static final AtomicInteger activeInstances = new AtomicInteger(0);

    private static final AtomicBoolean urlSetReady = new AtomicBoolean(false);

    private final AtomicBoolean destroyCalled = new AtomicBoolean(false);

    @Setter(AccessLevel.PACKAGE) private WebDriver testDriver;
    @Setter(AccessLevel.PACKAGE) private ExtensionClientIntegration extensionClientIntegration;

    private Browser preferredBrowser = DEFAULT_BROWSER;


    private static final Pattern INPUT_TAG_PATTERN = Pattern.compile(
            "<(input|textarea)(?:\\s[^>]*)?>",
            Pattern.CASE_INSENSITIVE | Pattern.DOTALL);

    private static final Pattern ID_FROM_FINDING = Pattern.compile("\\bid=([^\\s]+)");


    @Override
    public void init() {
        destroyCalled.set(false);
        preferredBrowser = resolvePreferredBrowser();
        int instances = activeInstances.incrementAndGet();
        LOGGER.debug("CSTI: init() active instance count={}", instances);

        if (urlSetReady.compareAndSet(false, true)) {
            scannedKeys.clear();
            LOGGER.debug("CSTI: scannedKeys cleared for new scan run.");
        }

        initSharedDriver();
    }

    @Override
    public void setTimeFinished() {
        super.setTimeFinished();
        destroy();
    }

    public void destroy() {
        if (!destroyCalled.compareAndSet(false, true)) return;

        browserLock.lock();
        try {
            int remaining = activeInstances.decrementAndGet();
            if (remaining < 0) {
                activeInstances.set(0);
                remaining = 0;
                LOGGER.warn("CSTI: active instance count went negative; reset to 0.");
            }
            if (remaining > 0) {
                LOGGER.debug("CSTI: keeping WebDriver alive, remaining instances={}", remaining);
                return;
            }

            urlSetReady.set(false);

            WebDriver driver = sharedDriver.getAndSet(null);
            if (driver != null) {
                try {
                    driver.quit();
                    LOGGER.info("CSTI: WebDriver closed.");
                } catch (Exception e) {
                    LOGGER.debug("CSTI: error closing WebDriver: {}", e.getMessage());
                }
            }
        } finally {
            browserLock.unlock();
        }
    }

    void initSharedDriver() {
        browserLock.lock();
        try {
            if (testDriver != null) {
                sharedDriver.set(testDriver);
                LOGGER.debug("CSTI: test WebDriver installed.");
                return;
            }

            WebDriver existing = sharedDriver.get();
            if (isDriverUsable(existing)) {
                LOGGER.debug("CSTI: reusing existing shared WebDriver.");
                return;
            }

            if (existing != null) {
                try { existing.quit(); } catch (Exception ignored) {}
                sharedDriver.set(null);
            }

            ExtensionSelenium extSelenium =
                    Control.getSingleton().getExtensionLoader().getExtension(ExtensionSelenium.class);
            if (extSelenium == null) {
                LOGGER.warn("CSTI: Selenium add-on not available – engine detection disabled.");
                return;
            }

            int proxyPort = Model.getSingleton().getOptionsParam().getProxyParam().getProxyPort();
            try {
                WebDriver driver = ExtensionSelenium.getWebDriver(
                        HttpSender.ACTIVE_SCANNER_INITIATOR,
                        preferredBrowser,
                        "127.0.0.1",
                        proxyPort,
                        capabilities -> capabilities.setCapability(
                                org.openqa.selenium.remote.CapabilityType.UNHANDLED_PROMPT_BEHAVIOUR,
                                org.openqa.selenium.UnexpectedAlertBehaviour.IGNORE),
                        false);

                driver.manage().timeouts().pageLoadTimeout(
                        java.time.Duration.of(10, java.time.temporal.ChronoUnit.SECONDS));
                driver.manage().timeouts().scriptTimeout(
                        java.time.Duration.of(10, java.time.temporal.ChronoUnit.SECONDS));

                sharedDriver.set(driver);
                LOGGER.info("CSTI: WebDriver started with {} (proxy port {}).", preferredBrowser, proxyPort);
            } catch (Exception e) {
                LOGGER.warn("CSTI: failed to start {} WebDriver: {}", preferredBrowser, e.getMessage());
            }
        } finally {
            browserLock.unlock();
        }
    }

    private Browser resolvePreferredBrowser() {
        String browserId = null;
        try {
            browserId = getConfig().getString(RULE_BROWSER_ID, DEFAULT_BROWSER.getId());
        } catch (ConversionException e) {
            LOGGER.debug("Invalid value for '{}': {}", RULE_BROWSER_ID, getConfig().getString(RULE_BROWSER_ID));
        }
        return resolvePreferredBrowser(browserId);
    }

    Browser resolvePreferredBrowser(String browserId) {
        if (browserId == null || browserId.isEmpty()) return DEFAULT_BROWSER;
        Browser browser = Browser.getBrowserWithIdNoFailSafe(browserId);
        if (browser == null) return DEFAULT_BROWSER;
        if (!isSupportedBrowser(browser)) {
            LOGGER.warn("Browser {} not supported, defaulting to: {}", browser, DEFAULT_BROWSER);
            return DEFAULT_BROWSER;
        }
        return browser;
    }

    private static boolean isSupportedBrowser(Browser browser) {
        return browser == Browser.FIREFOX || browser == Browser.FIREFOX_HEADLESS
                || browser == Browser.CHROME || browser == Browser.CHROME_HEADLESS
                || browser == Browser.EDGE   || browser == Browser.EDGE_HEADLESS;
    }


    @Override
    public void scan() {
        if (isStop()) return;

        HttpMessage msg    = getBaseMsg();
        String fullUrl     = msg.getRequestHeader().getURI().toString();

        LOGGER.debug("CSTI: scan() entered for {}", fullUrl);

        String dedupKey = deduplicationKey(fullUrl);
        if (!scannedKeys.add(dedupKey)) {
            LOGGER.debug("CSTI: skipping already-scanned page (key={})", dedupKey);
            return;
        }

        ExtensionClientIntegration extClient = resolveClientExtension();
        if (extClient == null) {
            LOGGER.debug("CSTI: Client add-on not available – skipping {}.", fullUrl);
            return;
        }

        // Phase A – gather injection surfaces.
        List<String> inputFindings = new ArrayList<>();
        List<String> linkFindings  = new ArrayList<>();

        ClientNode node = resolveNode(extClient, fullUrl);
        if (node != null) {
            collectFindings(node, inputFindings, linkFindings);
            LOGGER.debug("CSTI: spider yielded {} input(s), {} link(s) for {}",
                    inputFindings.size(), linkFindings.size(), fullUrl);
        } else {
            LOGGER.debug("CSTI: no client spider node for {}.", fullUrl);
        }

        supplementFromResponseHtml(msg, inputFindings);

        List<String> allFindings = new ArrayList<>(inputFindings);
        allFindings.addAll(linkFindings);

        if (allFindings.isEmpty()) {
            LOGGER.debug("CSTI: no usable components for {} (spider + HTML both empty).", fullUrl);
            return;
        }

        // Phase B – engine detection.
        String canonicalUrl = deduplicationKey(fullUrl);
        ClientSideEngineDetector.DetectionResult engine = detectEngine(canonicalUrl);
        EngineConfidence engineConfidence = scoreEngineDetectionConfidence(engine);

        // Step-1 alert.
        LOGGER.info("CSTI step-1: {} input(s), {} link(s) for {}",
                inputFindings.size(), linkFindings.size(), fullUrl);
        allFindings.forEach(f -> LOGGER.info("  {}", f));

        newAlert()
                .setRisk(Alert.RISK_INFO)
                .setConfidence(Alert.CONFIDENCE_HIGH)
                .setName(getName() + " [step-1 discovery]")
                .setDescription("Client Spider data found for this URL.")
                .setOtherInfo(String.join("\n", allFindings))
                .setMessage(msg)
                .raise();

        // Step-2 alert.
        newAlert()
                .setRisk(Alert.RISK_INFO)
                .setConfidence(toZapAlertConfidence(engineConfidence))
                .setName(getName() + " [step-2 engine detection]")
                .setDescription(buildEngineDetectionReport(inputFindings, linkFindings, engine, engineConfidence))
                .setMessage(msg)
                .raise();
    }


    String deduplicationKey(String fullUrl) {
        String bare = stripQueryAndFragment(fullUrl);
        if (bare == null) return fullUrl;
        int end = bare.length();
        while (end > 1 && bare.charAt(end - 1) == '/') end--;
        return end == bare.length() ? bare : bare.substring(0, end);
    }


    private ClientNode resolveNode(ExtensionClientIntegration extClient, String fullUrl) {
        ClientNode node = extClient.getClientNode(fullUrl, false, false);
        if (node != null) return node;

        String bare = stripQueryAndFragment(fullUrl);
        if (!bare.equals(fullUrl)) {
            node = extClient.getClientNode(bare, false, false);
            if (node != null) return node;

            node = extClient.getClientNode(bare + "/", false, false);
            if (node != null) return node;
        } else if (!fullUrl.endsWith("/")) {
            node = extClient.getClientNode(fullUrl + "/", false, false);
            if (node != null) return node;
        }

        return null;
    }


    private static void supplementFromResponseHtml(HttpMessage msg, List<String> inputFindings) {
        String body = msg.getResponseBody().toString();
        if (body == null || body.isBlank()) return;

        Set<String> knownIds = buildKnownIdSet(inputFindings);

        Matcher tagMatcher = INPUT_TAG_PATTERN.matcher(body);
        while (tagMatcher.find()) {
            String tag  = tagMatcher.group(1);
            String elem = tagMatcher.group(0);

            String type = extractAttr(elem, "type");
            if (isNonInjectable(type)) continue;

            String id   = extractAttr(elem, "id");
            String name = extractAttr(elem, "name");

            if (isKnown(id, knownIds) || isKnown(name, knownIds)) continue;

            inputFindings.add(String.format(
                    "type=%-14s  tag=%-10s  id=%-20s  name=%-20s  [static HTML]",
                    "HTML_PARSED",
                    tag.toUpperCase(),
                    nullToEmpty(id),
                    nullToEmpty(name)));
        }
    }

    private static Set<String> buildKnownIdSet(List<String> inputFindings) {
        Set<String> known = new HashSet<>();
        for (String finding : inputFindings) {
            Matcher m = ID_FROM_FINDING.matcher(finding);
            if (m.find()) {
                String id = m.group(1).trim();
                if (!id.isBlank() && !"-".equals(id)) {
                    known.add(id.toLowerCase(Locale.ROOT));
                }
            }
        }
        return known;
    }

    private static boolean isNonInjectable(String type) {
        return "hidden".equalsIgnoreCase(type) || "submit".equalsIgnoreCase(type)
                || "button".equalsIgnoreCase(type) || "image".equalsIgnoreCase(type)
                || "reset".equalsIgnoreCase(type);
    }

    private static boolean isKnown(String attr, Set<String> knownIds) {
        return attr != null && !attr.isBlank()
                && knownIds.contains(attr.toLowerCase(Locale.ROOT));
    }

    static String extractAttr(String tag, String attrName) {
        Pattern p = Pattern.compile(
                "\\b" + Pattern.quote(attrName) + "\\s*=\\s*(?:\"([^\"]*)\"|'([^']*)'|([^\\s>]*))",
                Pattern.CASE_INSENSITIVE);
        Matcher m = p.matcher(tag);
        if (!m.find()) return null;
        for (int g = 1; g <= m.groupCount(); g++) {
            String v = m.group(g);
            if (v != null) return v;
        }
        return null;
    }


    private ClientSideEngineDetector.DetectionResult detectEngine(String url) {
        LOGGER.info("CSTI: step-2 engine detection starting for {}", url);
        long lockStart = System.nanoTime();
        browserLock.lock();
        try {
            long waitedMs = (System.nanoTime() - lockStart) / 1_000_000;
            if (waitedMs > 0) LOGGER.debug("CSTI: waited {} ms for browser lock (url={})", waitedMs, url);

            WebDriver driver = sharedDriver.get();
            if (!isDriverUsable(driver)) {
                LOGGER.warn("CSTI: WebDriver not usable for {}, re-initialising.", url);
                initSharedDriver();
                driver = sharedDriver.get();
            }
            if (!isDriverUsable(driver)) {
                LOGGER.warn("CSTI: no usable WebDriver after re-init for {}.", url);
                return new ClientSideEngineDetector.DetectionResult("unknown", "");
            }

            ClientSideEngineDetector.DetectionResult result = ClientSideEngineDetector.detect(driver, url);
            LOGGER.info("CSTI: step-2 result for {} -> {}", url, result);
            return result;
        } finally {
            browserLock.unlock();
        }
    }

    private static boolean isDriverUsable(WebDriver driver) {
        if (driver == null) return false;
        try {
            driver.getWindowHandles();
            return true;
        } catch (Exception e) {
            LOGGER.debug("CSTI: WebDriver unusable ({}): {}", e.getClass().getSimpleName(), e.getMessage());
            return false;
        }
    }


    private ExtensionClientIntegration resolveClientExtension() {
        if (extensionClientIntegration != null) return extensionClientIntegration;
        return Control.getSingleton().getExtensionLoader().getExtension(ExtensionClientIntegration.class);
    }

    private void collectFindings(ClientNode node, List<String> inputFindings, List<String> linkFindings) {
        ClientSideDetails details = node.getUserObject();
        if (details == null) return;

        for (ClientSideComponent component : details.getComponents()) {
            if (component.getType() != ClientSideComponent.Type.NODE_ADDED) continue;

            String tag = component.getTagName();
            if (tag == null || tag.isBlank()) continue;

            if (tag.equalsIgnoreCase("input") || tag.equalsIgnoreCase("textarea")) {
                String line = describeInput(component);
                if (line != null) inputFindings.add(line);
            } else if (tag.equalsIgnoreCase("a")) {
                String line = describeLink(component);
                if (line != null) linkFindings.add(line);
            }
        }
    }

    private static String describeInput(ClientSideComponent component) {
        String tag = component.getTagName();
        if (component.isStorageEvent()) {
            return String.format("type=%-14s  tag=%-10s  id=%-20s",
                    component.getType(), nullToEmpty(tag), nullToEmpty(component.getId()));
        }
        return String.format("type=%-14s  tag=%-10s  id=%-20s",
                component.getType(), nullToEmpty(tag), nullToEmpty(component.getId()));
    }

    private static String describeLink(ClientSideComponent component) {
        String href = component.getHref();
        if (href == null || !href.contains("?")) return null;
        return String.format("type=%-14s  tag=%-10s  id=%-20s  href=%s",
                component.getType(), nullToEmpty(component.getTagName()),
                nullToEmpty(component.getId()), href);
    }


    static EngineConfidence scoreEngineDetectionConfidence(
            ClientSideEngineDetector.DetectionResult engine) {

        boolean hasGlobal = engine.detected();
        boolean hasActivity = engine.hasActiveCalls();
        boolean hasTagEvidence = engine.hasTagEvidence();

        // Heuristic 3 is only applicable if the detected engine has known tag/script markers.
        boolean heuristic3Applicable = hasGlobal
                && ClientSideEngineDetector.isTagHeuristicApplicable(engine.engineName());

        if (hasGlobal && hasTagEvidence) {
            return EngineConfidence.VERY_HIGH;
        }

        if (hasGlobal && hasActivity) {
            return heuristic3Applicable ? EngineConfidence.HIGH : EngineConfidence.VERY_HIGH;
        }

        if (hasGlobal || hasTagEvidence) {
            return EngineConfidence.LOW;
        }

        return EngineConfidence.LOW;
    }

    private static int toZapAlertConfidence(EngineConfidence confidence) {
        return switch (confidence) {
            case LOW -> Alert.CONFIDENCE_LOW;
            case HIGH -> Alert.CONFIDENCE_MEDIUM;
            case VERY_HIGH -> Alert.CONFIDENCE_HIGH;
        };
    }

    private static String buildEngineDetectionReport(
            List<String> inputFindings,
            List<String> linkFindings,
            ClientSideEngineDetector.DetectionResult engine,
            EngineConfidence confidence) {

        StringBuilder sb = new StringBuilder();

        if (engine.detected()) {
            sb.append("Engine detected : ").append(engine.engineName()).append("\n");
            sb.append("Global checked  : ").append(engine.globalExpression()).append("\n\n");
            sb.append("Detection confidence : ").append(confidence).append("\n");
            sb.append("Heuristics: H1(global)=true, H2(activity)=")
                    .append(engine.hasActiveCalls())
                    .append(", H3(tags)=")
                    .append(engine.hasTagEvidence())
                    .append("\n\n");

            sb.append("Explicit render/compile calls:\n");
            if (engine.hasActiveCalls()) {
                engine.matchedCalls().forEach(c -> sb.append("  ").append(c).append("\n"));
            } else {
                sb.append("none found\n");
            }
            if (!engine.hasActiveCalls()) {
                sb.append("\nNote: library imported but no active render/compile calls confirmed.\n");
            }

            sb.append("\nScript-type template blocks (<script type=\"…\">):\n");
            if (!engine.matchedScriptTypes().isEmpty()) {
                engine.matchedScriptTypes().forEach(t -> sb.append("  ").append(t).append("\n"));
            } else {
                sb.append("none found\n");
            }

            sb.append("\n Custom template attributes in DOM:\n");
            if (!engine.matchedTemplateAttrs().isEmpty()) {
                engine.matchedTemplateAttrs().forEach(a -> sb.append("  ").append(a).append("\n"));
            } else {
                sb.append("none found\n");
            }

            if (!engine.hasTagEvidence()) {
                sb.append("\nNote: no tag evidence found "
                        + "(no script-type blocks, no custom template attributes).\n");
            }

        } else {
            sb.append("Engine : not detected via JS global check\n");
            sb.append("Detection confidence : ").append(confidence).append("\n");
        }

        sb.append("\nInjection surfaces on this page:\n");
        if (inputFindings.isEmpty()) {
            sb.append("  none\n");
        } else {
            inputFindings.forEach(f -> sb.append("  ").append(f).append("\n"));
        }

        if (!linkFindings.isEmpty()) {
            sb.append("\nLinks to other pages:\n");
            linkFindings.forEach(f -> sb.append("  ").append(f).append("\n"));
        }

        return sb.toString().trim();
    }


    private static String nullToEmpty(String value) {
        return value != null ? value : "-";
    }

    String stripQueryAndFragment(String fullUrl) {
        if (fullUrl == null) return null;
        int q   = fullUrl.indexOf('?');
        int f   = fullUrl.indexOf('#');
        int cut;
        if      (q == -1) cut = f;
        else if (f == -1) cut = q;
        else              cut = Math.min(q, f);
      return cut >= 0 ? fullUrl.substring(0, cut) : fullUrl;
    }


    @Override public int    getId()          { return PLUGIN_ID; }
    @Override public int    getCategory()    { return Category.INJECTION; }
    @Override public String getName()        { return Constant.messages.getString(MESSAGE_PREFIX + "name"); }
    @Override public String getDescription() { return Constant.messages.getString(MESSAGE_PREFIX + "desc"); }
    @Override public String getSolution()    { return Constant.messages.getString(MESSAGE_PREFIX + "soln"); }
    @Override public String getReference()   { return Constant.messages.getString(MESSAGE_PREFIX + "refs"); }
}