package com.chensoul.security;

import org.htmlunit.Page;
import org.htmlunit.WebClient;
import org.htmlunit.WebResponse;
import org.htmlunit.html.HtmlButton;
import org.htmlunit.html.HtmlElement;
import org.htmlunit.html.HtmlInput;
import org.htmlunit.html.HtmlPage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration tests for the sample Authorization Server.
 *
 * @author Daniel Garnier-Moiroux
 */
@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
public class AuthServerApplicationTests {
    private static final String REDIRECT_URI = "http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc";

    private static final String AUTHORIZATION_REQUEST = UriComponentsBuilder
            .fromPath("/oauth2/authorize")
            .queryParam("response_type", "code")
            .queryParam("client_id", "messaging-client")
            .queryParam("scope", "openid")
            .queryParam("state", "some-state")
            .queryParam("redirect_uri", REDIRECT_URI)
            .toUriString();

    @Autowired
    private WebClient webClient;

    private static <P extends Page> P signIn(HtmlPage page, String username, String password) throws IOException {
        HtmlInput usernameInput = page.querySelector("input[name=\"username\"]");
        HtmlInput passwordInput = page.querySelector("input[name=\"password\"]");
        HtmlButton signInButton = page.querySelector("button");

        usernameInput.type(username);
        passwordInput.type(password);
        return signInButton.click();
    }

    private static void assertLoginPage(HtmlPage page) {
        assertThat(page.getUrl().toString()).endsWith("/login");

        HtmlInput usernameInput = page.querySelector("input[name=\"username\"]");
        HtmlInput passwordInput = page.querySelector("input[name=\"password\"]");
        HtmlButton signInButton = page.querySelector("button");

        assertThat(usernameInput).isNotNull();
        assertThat(passwordInput).isNotNull();
        assertThat(signInButton.getTextContent()).isEqualTo("Sign in");
    }

    @BeforeEach
    public void setUp() {
        this.webClient.getOptions().setThrowExceptionOnFailingStatusCode(true);
        this.webClient.getOptions().setRedirectEnabled(true);
        this.webClient.getCookieManager().clearCookies();    // log out
    }

    @Test
    public void whenLoginSuccessfulThenDisplayNotFoundError() throws IOException {
        HtmlPage page = this.webClient.getPage("/");

        assertLoginPage(page);

        this.webClient.getOptions().setThrowExceptionOnFailingStatusCode(false);
        WebResponse signInResponse = signIn(page, "user1", "password").getWebResponse();
        assertThat(signInResponse.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND.value());    // there is no "default" index page
    }

    @Test
    public void whenLoginFailsThenDisplayBadCredentials() throws IOException {
        HtmlPage page = this.webClient.getPage("/");

        HtmlPage loginErrorPage = signIn(page, "user1", "wrong-password");

        HtmlElement alert = loginErrorPage.querySelector("div[role=\"alert\"]");
        assertThat(alert).isNotNull();
        assertThat(alert.getTextContent()).isEqualTo("Invalid credentials");
    }

    @Test
    public void whenNotLoggedInAndRequestingTokenThenRedirectsToLogin() throws IOException {
        HtmlPage page = this.webClient.getPage(AUTHORIZATION_REQUEST);

        assertLoginPage(page);
    }

    @Test
    public void whenLoggingInAndRequestingTokenThenRedirectsToClientApplication() throws IOException {
        // Log in
        this.webClient.getOptions().setThrowExceptionOnFailingStatusCode(false);
        this.webClient.getOptions().setRedirectEnabled(false);
        signIn(this.webClient.getPage("/login"), "user1", "password");

        // Request token
        WebResponse response = this.webClient.getPage(AUTHORIZATION_REQUEST).getWebResponse();

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.MOVED_PERMANENTLY.value());
        String location = response.getResponseHeaderValue("location");
        assertThat(location).startsWith(REDIRECT_URI);
        assertThat(location).contains("code=");
    }

}