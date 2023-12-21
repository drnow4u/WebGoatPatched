package org.owasp.webgoat;

import io.restassured.RestAssured;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class CSPIntegrationTest extends IntegrationTest {

    @ParameterizedTest
    @ValueSource(strings = {
            "/SpoofCookie/login",
            "/challenge/logo",
            "/InsecureLogin/task"
    })
    void shouldPostResponseContainsCSPHeaders(String url) {
        RestAssured.given()
                .when()
                .relaxedHTTPSValidation()
//                .cookie("JSESSIONID", getWebGoatCookie())
//                .formParam("username", getUser())
//                .formParam("password", "password")
                .post(url(url))
                .then()
//                .statusCode(302)
//                .header("Location", containsString("/login"))
                .header("referrer-policy", "strict-origin")
                .header("content-security-policy", "style-src 'self' 'unsafe-inline'; worker-src 'none'; child-src 'none'; script-src 'self'; frame-src 'self' blob:; connect-src 'self'; img-src 'self' data:; default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; block-all-mixed-content; upgrade-insecure-requests;")
                .header("x-content-type-options", "nosniff")
                .header("x-frame-options", "DENY")
                .header("x-xss-protection", "1; mode=block");
    }
}
