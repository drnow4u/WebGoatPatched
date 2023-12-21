package org.owasp.webgoat;

import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;

/**
 * Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate
 * certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These
 * attacks are used for everything from data theft to site defacement or distribution of malware.
 * CSP provides a set of standard HTTP headers that allow website owners to declare approved sources
 * of content that browsers should be allowed to load on that page — covered types are JavaScript,
 * CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and
 * video files.
 *
 * <p>CWE-693: Protection Mechanism Failure https://cwe.mitre.org/data/definitions/693.html WASC-15
 * http://projects.webappsec.org/w/page/13246914/Application%20Misconfiguration
 *
 * <p>Solution: Ensure that your web server, application server, load balancer, etc. is configured
 * to set the Content-Security-Policy header.
 *
 * @see
 *     https://developer.mozilla.org/en-US/docs/Web/Security/CSP/Introducing_Content_Security_Policy
 * @see https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html
 * @see http://www.w3.org/TR/CSP/
 * @see http://w3c.github.io/webappsec/specs/content-security-policy/csp-specification.dev.html
 * @see http://www.html5rocks.com/en/tutorials/security/content-security-policy/
 * @see http://caniuse.com/#feat=contentsecuritypolicy
 * @see http://content-security-policy.com/
 *     <p>OWASP_2021_A05 https://owasp.org/Top10/A05_2021-Security_Misconfiguration/ OWASP_2017_A06
 *     https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration.html
 */
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true, jsr250Enabled = true)
// @EnableWebSecurity
public class CspPolicyConfig {

  private static final int LEAP_YEAR_IN_SECONDS = 366 * 24 * 60 * 60;
  private static final String CSP_POLICY =
      String.join(
          " ",
          "style-src 'self' 'unsafe-inline';",
          "worker-src 'none';",
          "child-src 'none';",
          "script-src 'self';",
          "frame-src 'self' blob:;",
          "connect-src 'self';",
          "img-src 'self' data:;",
          "default-src 'self';",
          "base-uri 'self';",
          "object-src 'none';",
          "frame-ancestors 'none';",
          "form-action 'self';",
          "block-all-mixed-content;",
          "upgrade-insecure-requests;");

  public static void setupSecurityHeaders(HttpSecurity http) throws Exception {
    http.headers()
        .httpStrictTransportSecurity()
        .includeSubDomains(true)
        .maxAgeInSeconds(LEAP_YEAR_IN_SECONDS)
        .and()
        .xssProtection()
        .xssProtectionEnabled(true)
        .block(true)
        .and()
        .contentSecurityPolicy(CSP_POLICY)
        .and()
        .contentTypeOptions()
        .and()
        .frameOptions()
        .deny()
        .cacheControl()
        .and()
        .referrerPolicy(ReferrerPolicyHeaderWriter.ReferrerPolicy.STRICT_ORIGIN);
  }
}
