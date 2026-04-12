package org.zaproxy.zap.extension.ascanrulesAlpha;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
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

    private static final Logger LOGGER = LogManager.getLogger(CstiActiveScanRule.class);
    private static final int PLUGIN_ID = 553542;
    private static final String MESSAGE_PREFIX = "ascanalpha.csti.";
    private static final String RULE_BROWSER_ID = "rules.ascanalpha.csti.browserid";
    private static final Browser DEFAULT_BROWSER = Browser.FIREFOX_HEADLESS;

    private static final AtomicReference<WebDriver> sharedDriver = new AtomicReference<>(null);

    private static final java.util.concurrent.locks.ReentrantLock browserLock =
            new java.util.concurrent.locks.ReentrantLock();

    private static final Set<String> scannedUrls = ConcurrentHashMap.newKeySet();

    private static final AtomicInteger activeInstances = new AtomicInteger(0);

    private final AtomicBoolean destroyCalled = new AtomicBoolean(false);

    /** Test seam for injecting a mocked driver, not used in production flow. */
    @Setter(AccessLevel.PACKAGE)
    private WebDriver testDriver;

    /** Test seam for injecting mocked client integration, not used in production flow. */
    @Setter(AccessLevel.PACKAGE)
    private ExtensionClientIntegration extensionClientIntegration;

    private Browser preferredBrowser = DEFAULT_BROWSER;

    @Override
    public void init() {
        scannedUrls.clear();
        destroyCalled.set(false);
        preferredBrowser = resolvePreferredBrowser();
        int instances = activeInstances.incrementAndGet();
        LOGGER.debug("CSTI: init() active instance count={}", instances);

        initSharedDriver();
    }

    @Override
    public void setTimeFinished() {
        super.setTimeFinished();
        destroy();
    }

    public void destroy() {
        if (!destroyCalled.compareAndSet(false, true)) {
            return;
        }

        browserLock.lock();
        try {
        int remaining = activeInstances.decrementAndGet();
        if (remaining < 0) {
            activeInstances.set(0);
            remaining = 0;
            LOGGER.warn("CSTI: active instance count went negative; reset to 0.");
        }

        if (remaining > 0) {
            LOGGER.debug("CSTI: keeping shared WebDriver alive, remaining instances={}", remaining);
            return;
        }

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
            try {
                existing.quit();
            } catch (Exception e) {
                LOGGER.debug("CSTI: error closing unusable WebDriver: {}", e.getMessage());
            } finally {
                sharedDriver.set(null);
            }
        }

        ExtensionSelenium extSelenium =
                Control.getSingleton()
                        .getExtensionLoader()
                        .getExtension(ExtensionSelenium.class);

        if (extSelenium == null) {
            LOGGER.warn("CSTI: Selenium add-on not available — engine detection disabled.");
            return;
        }

        int proxyPort =
                Model.getSingleton()
                        .getOptionsParam()
                        .getProxyParam()
                        .getProxyPort();

        try {
            WebDriver driver =
                    ExtensionSelenium.getWebDriver(
                            HttpSender.ACTIVE_SCANNER_INITIATOR,
                            preferredBrowser,
                            "127.0.0.1",
                            proxyPort,
                            capabilities ->
                                    capabilities.setCapability(
                                            org.openqa.selenium.remote.CapabilityType
                                                    .UNHANDLED_PROMPT_BEHAVIOUR,
                                            org.openqa.selenium.UnexpectedAlertBehaviour.IGNORE),
                            false);

            driver.manage()
                    .timeouts()
                    .pageLoadTimeout(
                            java.time.Duration.of(10, java.time.temporal.ChronoUnit.SECONDS));
            driver.manage()
                    .timeouts()
                    .scriptTimeout(
                            java.time.Duration.of(10, java.time.temporal.ChronoUnit.SECONDS));

            sharedDriver.set(driver);
            LOGGER.info(
                    "CSTI: WebDriver started with {} (proxy port {}).",
                    preferredBrowser,
                    proxyPort);
        } catch (Exception e) {
            LOGGER.warn(
                    "CSTI: failed to start {} WebDriver, engine detection disabled: {}",
                    preferredBrowser,
                    e.getMessage());
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
            LOGGER.debug(
                    "Invalid value for '{}': {}",
                    RULE_BROWSER_ID,
                    getConfig().getString(RULE_BROWSER_ID));
        }
        return resolvePreferredBrowser(browserId);
    }

    Browser resolvePreferredBrowser(String browserId) {
        Browser browser = null;
        if (browserId != null && !browserId.isEmpty()) {
            browser = Browser.getBrowserWithIdNoFailSafe(browserId);
        }
        if (browser == null) {
            return DEFAULT_BROWSER;
        }
        if (!isSupportedBrowser(browser)) {
            LOGGER.warn(
                    "Specified browser {} is not supported, defaulting to: {}",
                    browser,
                    DEFAULT_BROWSER);
            return DEFAULT_BROWSER;
        }
        return browser;
    }

    private static boolean isSupportedBrowser(Browser browser) {
        return browser == Browser.FIREFOX
                || browser == Browser.FIREFOX_HEADLESS
                || browser == Browser.CHROME
                || browser == Browser.CHROME_HEADLESS
                || browser == Browser.EDGE
                || browser == Browser.EDGE_HEADLESS;
    }

    @Override
    public void scan() {
        if (isStop()) return;

        HttpMessage msg = getBaseMsg();
        String fullUrl = msg.getRequestHeader().getURI().toString();

        LOGGER.debug("CSTI: scan() entered for {}", fullUrl);

        if (!scannedUrls.add(fullUrl)) {
            LOGGER.debug("CSTI: skipping already-scanned URL: {}", fullUrl);
            return;
        }

        ExtensionClientIntegration extClient =
                (extensionClientIntegration != null)
                        ? extensionClientIntegration
                        : Control.getSingleton()
                          .getExtensionLoader()
                          .getExtension(ExtensionClientIntegration.class);

        if (extClient == null) {
            LOGGER.debug("CSTI: Client add-on not available.");
            raiseDebugAlert(msg, "Client add-on not available.", fullUrl);
            return;
        }

        ClientNode node = resolveNode(extClient, fullUrl);
        if (node == null) {
            LOGGER.debug("CSTI: no client spider node for {}.", fullUrl);
            raiseDebugAlert(msg, "No client spider node found for URL.", fullUrl);
            return;
        }

        List<String> findings = new ArrayList<>();
        collectFindings(node, findings);

        if (findings.isEmpty()) {
            LOGGER.debug("CSTI: node found for {} but no usable components.", fullUrl);
            raiseDebugAlert(msg, "Client node found, but no usable components.", fullUrl);
            return;
        }

        ClientSideEngineDetector.DetectionResult engine = detectEngine(fullUrl);

        LOGGER.info("CSTI step-1: {} component(s) for {}", findings.size(), fullUrl);
        findings.forEach(f -> LOGGER.info("  {}", f));

        newAlert()
                .setRisk(Alert.RISK_INFO)
                .setConfidence(Alert.CONFIDENCE_HIGH)
                .setName(getName() + " [step-1 discovery]")
                .setDescription("Client Spider data found for this URL.")
                .setOtherInfo(String.join("\n", findings))
                .setMessage(msg)
                .raise();

        newAlert()
                .setRisk(Alert.RISK_INFO)
                .setConfidence(Alert.CONFIDENCE_HIGH)
                .setName(getName() + " [step-2 engine detection]")
                .setDescription(buildEngineDetectionReport(findings, engine))
                .setMessage(msg)
                .raise();
    }

    private ClientSideEngineDetector.DetectionResult detectEngine(String url) {
        LOGGER.info("CSTI: step-2 engine detection starting for {}", url);
        long lockStart = System.nanoTime();
        browserLock.lock();
        try {
            long waitedMs = (System.nanoTime() - lockStart) / 1_000_000;
            if (waitedMs > 0) {
                LOGGER.debug("CSTI: waited {} ms for browser lock (url={})", waitedMs, url);
            }

            WebDriver driver = sharedDriver.get();
            if (!isDriverUsable(driver)) {
                LOGGER.warn("CSTI: shared WebDriver is not usable for {}, attempting re-init.", url);
                initSharedDriver();
                driver = sharedDriver.get();
            }
            if (!isDriverUsable(driver)) {
                LOGGER.warn("CSTI: no usable WebDriver after re-init, skipping engine detection for {}", url);
                return new ClientSideEngineDetector.DetectionResult("unknown", "");
            }

            ClientSideEngineDetector.DetectionResult result =
                    ClientSideEngineDetector.detect(driver, url);
            LOGGER.info("CSTI: step-2 engine detection result for {} -> {}", url, result);
            return result;
        } finally {
            browserLock.unlock();
        }
    }

    private static boolean isDriverUsable(WebDriver driver) {
        if (driver == null) {
            return false;
        }
        try {
            driver.getWindowHandles();
            return true;
        } catch (Exception e) {
            LOGGER.debug(
                    "CSTI: shared WebDriver unusable ({}): {}",
                    e.getClass().getSimpleName(),
                    e.getMessage());
            return false;
        }
    }

    private ClientNode resolveNode(ExtensionClientIntegration extClient, String fullUrl) {
        ClientNode node = extClient.getClientNode(fullUrl, false, false);
        if (node != null) return node;

        String bare = stripQueryAndFragment(fullUrl);
        if (!bare.equals(fullUrl)) {
            node = extClient.getClientNode(bare, false, false);
            if (node != null) return node;
        }

        if (!fullUrl.endsWith("/") && !fullUrl.contains("?") && !fullUrl.contains("#")) {
            node = extClient.getClientNode(fullUrl + "/", false, false);
        }
        return node;
    }

    private void raiseDebugAlert(HttpMessage msg, String reason, String fullUrl) {
        newAlert()
                .setRisk(Alert.RISK_INFO)
                .setConfidence(Alert.CONFIDENCE_HIGH)
                .setName(getName() + " [debug]")
                .setDescription(reason)
                .setOtherInfo("URL: " + fullUrl)
                .setMessage(msg)
                .raise();
    }

    String stripQueryAndFragment(String fullUrl) {
        if (fullUrl == null) return null;
        int q = fullUrl.indexOf('?');
        int f = fullUrl.indexOf('#');
        int cut;
        if (q == -1)      cut = f;
        else if (f == -1) cut = q;
        else              cut = Math.min(q, f);
        return cut >= 0 ? fullUrl.substring(0, cut) : fullUrl;
    }

    private void collectFindings(ClientNode node, List<String> findings) {
        ClientSideDetails details = node.getUserObject();
        if (details == null) return;
        for (ClientSideComponent component : details.getComponents()) {
            String line = describeComponent(component);
            if (line != null) findings.add(line);
        }
    }

    private static String describeComponent(ClientSideComponent component) {
        ClientSideComponent.Type type = component.getType();
        String tag = component.getTagName();

        if (type != ClientSideComponent.Type.NODE_ADDED) return null;
        if (tag == null || tag.isBlank()) return null;

        boolean isInjectable =
                tag.equalsIgnoreCase("input")
                        || tag.equalsIgnoreCase("textarea")
                        || tag.equalsIgnoreCase("a");
        if (!isInjectable) return null;

        if (tag.equalsIgnoreCase("a")) {
            String href = component.getHref();
            if (href == null || !href.contains("?")) return null;
        }

        if (component.isStorageEvent()) {
            return String.format(
                    "type=%-14s  tag=%-10s  id=%-20s  [storage event]",
                    type, nullToEmpty(tag), nullToEmpty(component.getId()));
        }

        return String.format(
                "type=%-14s  tag=%-10s  id=%-20s  href=%s",
                type,
                nullToEmpty(component.getTagName()),
                nullToEmpty(component.getId()),
                nullToEmpty(component.getHref()));
    }

    private static String buildEngineDetectionReport(
            List<String> findings, ClientSideEngineDetector.DetectionResult engine) {

        StringBuilder sb = new StringBuilder();

        if (engine.detected()) {
            sb.append("Engine detected : ").append(engine.engineName()).append("\n");
            sb.append("Global checked  : ").append(engine.globalExpression()).append("\n");
        } else {
            sb.append("Engine : not detected via JS global check\n");
        }

        sb.append("\nInjection points:\n");
        findings.forEach(f -> sb.append(f).append("\n"));
        return sb.toString().trim();
    }

    private static String nullToEmpty(String value) {
        return value != null ? value : "-";
    }

    @Override public int getId()             { return PLUGIN_ID; }
    @Override public int getCategory()       { return Category.INJECTION; }
    @Override public String getName()        { return Constant.messages.getString(MESSAGE_PREFIX + "name"); }
    @Override public String getDescription() { return Constant.messages.getString(MESSAGE_PREFIX + "desc"); }
    @Override public String getSolution()    { return Constant.messages.getString(MESSAGE_PREFIX + "soln"); }
    @Override public String getReference()   { return Constant.messages.getString(MESSAGE_PREFIX + "refs"); }
}