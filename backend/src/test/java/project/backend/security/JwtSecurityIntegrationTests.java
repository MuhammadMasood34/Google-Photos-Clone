package project.backend.security;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.web.SpringJUnitWebConfig;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import project.backend.config.AppConfig;
import project.backend.config.SecurityConfig;
import project.backend.services.JwtService;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringJUnitWebConfig({ SecurityConfig.class, AppConfig.class, JwtAuthenticationFilter.class, JwtService.class,
        JwtSecurityIntegrationTests.TestConfiguration.class })
@TestPropertySource(properties = {
        "app.jwt.secret=test-secret-with-at-least-32-bytes-long",
        "app.jwt.access-expiration-ms=900000",
        "app.jwt.refresh-expiration-ms=604800000",
        "app.cors.allowed-origins=http://localhost:3000"
})
class JwtSecurityIntegrationTests {

    @Autowired
    private WebApplicationContext context;

    @Autowired
    private FilterRegistrationBean<JwtAuthenticationFilter> registration;

    @Autowired
    private JwtService jwtService;

    private MockMvc mvc;

    @BeforeEach
    void setUp() {
        mvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
    }

    @Test
    void protectedEndpointRequiresAuthentication() throws Exception {
        mvc.perform(get("/api/photos")).andExpect(status().isUnauthorized());
    }

    @Test
    void publicEndpointAllowsMissingToken() throws Exception {
        mvc.perform(get("/api/auth/login")).andExpect(status().isOk());
    }

    @Test
    void validTokenAuthenticatesOnlyTheCurrentRequest() throws Exception {
        var claims = new JWTClaimsSet.Builder().subject("user@example.com")
                .expirationTime(Date.from(Instant.now().plusSeconds(300))).build();
        var token = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims);
        token.sign(new MACSigner("test-secret-with-at-least-32-bytes-long".getBytes(StandardCharsets.UTF_8)));

        mvc.perform(get("/api/photos").header("Authorization", "Bearer " + token.serialize()))
                .andExpect(status().isOk())
                .andExpect(content().string("user@example.com"));
        mvc.perform(get("/api/photos")).andExpect(status().isUnauthorized());
    }

    @Test
    void invalidTokenReturnsUnauthorized() throws Exception {
        mvc.perform(get("/api/photos").header("Authorization", "Bearer invalid"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void serviceGeneratedTokenAuthenticatesThroughExistingFilter() throws Exception {
        var user = project.backend.domain.User.builder().id(UUID.randomUUID())
                .email("issued@example.com").build();

        mvc.perform(get("/api/photos")
                .header("Authorization", "Bearer " + jwtService.generateAccessToken(user)))
                .andExpect(status().isOk())
                .andExpect(content().string(user.getEmail()));
    }

    @Test
    void corsPreflightAllowsConfiguredFrontend() throws Exception {
        mvc.perform(options("/api/photos")
                .header("Origin", "http://localhost:3000")
                .header("Access-Control-Request-Method", "GET"))
                .andExpect(status().isOk())
                .andExpect(header().string("Access-Control-Allow-Origin", "http://localhost:3000"))
                .andExpect(header().string("Access-Control-Allow-Credentials", "true"));
    }

    @Test
    void jwtFilterIsNotRegisteredAsASeparateServletFilter() {
        assertFalse(registration.isEnabled());
    }

    @Configuration
    @EnableWebMvc
    static class TestConfiguration {

        @Bean
        TestController testController() {
            return new TestController();
        }

        @Bean
        UserDetailsService userDetailsService() {
            return new InMemoryUserDetailsManager(User.withUsername("test")
                    .password("unused").roles("USER").build());
        }
    }

    @RestController
    static class TestController {

        @GetMapping("/api/photos")
        String photos(Authentication authentication) {
            return authentication.getName();
        }

        @GetMapping("/api/auth/login")
        String login() {
            return "public";
        }
    }
}
