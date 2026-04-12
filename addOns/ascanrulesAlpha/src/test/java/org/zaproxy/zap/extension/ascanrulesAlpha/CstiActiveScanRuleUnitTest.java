/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.extension.ascanrulesAlpha;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.willThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.openqa.selenium.JavascriptExecutor;
import org.openqa.selenium.WebDriver;
import org.zaproxy.zap.extension.selenium.Browser;
import org.zaproxy.zap.extension.ascanrulesAlpha.scripts.ClientSideEngineDetector;
import org.zaproxy.zap.extension.ascanrulesAlpha.scripts.ClientSideEngineDetector.DetectionResult;

class CstiActiveScanRuleUnitTest {

	@Test
	void shouldDetectAngularWhenGlobalIsPresent() {
		// Given
		TestWebDriver driver = mock(TestWebDriver.class);
		given(driver.executeScript(anyString(), any())).willReturn(Boolean.TRUE);

		// When
		DetectionResult result =
				ClientSideEngineDetector.detect(driver, "http://example.test/?q={{7*7}}");

		// Then
		assertThat(result.detected(), is(equalTo(true)));
		assertThat(result.engineName(), is(equalTo("angular")));
		assertThat(result.globalExpression(), is(equalTo("angular.version")));
	}

	@Test
	void shouldReturnUnknownIfNavigationFails() {
		// Given
		TestWebDriver driver = mock(TestWebDriver.class);
		willThrow(new RuntimeException("navigation failed")).given(driver).get(anyString());

		// When
		DetectionResult result =
				ClientSideEngineDetector.detect(driver, "http://example.test/fail");

		// Then
		assertThat(result.detected(), is(equalTo(false)));
		assertThat(result.engineName(), is(equalTo("unknown")));
		verify(driver, never()).executeScript(anyString(), any());
	}

	@Test
	void shouldReturnUnknownWhenNoEngineIsDetected() {
		// Given
		TestWebDriver driver = mock(TestWebDriver.class);
		given(driver.executeScript(anyString(), any())).willReturn(Boolean.FALSE);

		// When
		DetectionResult result =
				ClientSideEngineDetector.detect(driver, "http://example.test/no-engine");

		// Then
		assertThat(result.detected(), is(equalTo(false)));
		assertThat(result.engineName(), is(equalTo("unknown")));
		assertThat(result.globalExpression(), is(equalTo("")));
	}

	@Test
	void shouldContinueChecksAfterScriptException() {
		// Given
		TestWebDriver driver = mock(TestWebDriver.class);
		AtomicInteger calls = new AtomicInteger(0);
		given(driver.executeScript(anyString(), any()))
				.willAnswer(
						invocation -> {
							if (calls.getAndIncrement() == 0) {
								throw new RuntimeException("first engine check failed");
							}
							return Boolean.TRUE;
						});

		// When
		DetectionResult result =
				ClientSideEngineDetector.detect(driver, "http://example.test/continue");

		// Then
		assertThat(result.detected(), is(equalTo(true)));
		assertThat(result.engineName(), is(equalTo("vue")));
		assertThat(result.globalExpression(), is(equalTo("Vue")));
	}

	@Test
	void shouldStripQueryAndFragmentFromUrl() {
		// Given
		CstiActiveScanRule rule = new CstiActiveScanRule();

		// When
		String stripped = rule.stripQueryAndFragment("https://example.test/path?a=1#frag");

		// Then
		assertThat(stripped, is(equalTo("https://example.test/path")));
	}

	@Test
	void shouldResolveSupportedBrowserId() {
		// Given
		CstiActiveScanRule rule = new CstiActiveScanRule();

		// When
		Browser resolved = rule.resolvePreferredBrowser(Browser.CHROME_HEADLESS.getId());

		// Then
		assertThat(resolved, is(equalTo(Browser.CHROME_HEADLESS)));
	}

	@Test
	void shouldDefaultWhenBrowserIdIsUnknown() {
		// Given
		CstiActiveScanRule rule = new CstiActiveScanRule();

		// When
		Browser resolved = rule.resolvePreferredBrowser("not-a-browser");

		// Then
		assertThat(resolved, is(equalTo(Browser.FIREFOX_HEADLESS)));
	}

	@Test
	void shouldDefaultWhenBrowserIdIsUnsupported() {
		// Given
		CstiActiveScanRule rule = new CstiActiveScanRule();

		// When
		Browser resolved = rule.resolvePreferredBrowser(Browser.HTML_UNIT.getId());

		// Then
		assertThat(resolved, is(equalTo(Browser.FIREFOX_HEADLESS)));
	}

	private interface TestWebDriver extends WebDriver, JavascriptExecutor {}
}

