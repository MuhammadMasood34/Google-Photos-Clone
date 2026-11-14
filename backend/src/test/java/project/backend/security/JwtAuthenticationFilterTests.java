package project.backend.security;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

import project.backend.config.JwtProperties;

import static org.junit.jupiter.api.Assertions.*;

class JwtAuthenticationFilterTests {

    private static final String SECRET = "test-secret-with-at-least-32-bytes-long";
    private JwtAuthenticationFilter filter;
    private MockHttpServletRequest request;
    private MockHttpServletResponse response;
    private MockFilterChain chain;

    @BeforeEach
    void setUp() {
        SecurityContextHolder.clearContext();
        filter = new JwtAuthenticationFilter(new JwtProperties(SECRET, 900000, 604800000));
        request = new MockHttpServletRequest("GET", "/api/photos");
        response = new MockHttpServletResponse();
        chain = new MockFilterChain();
    }

    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void validSignedTokenAuthenticatesItsSubject() throws Exception {
        request.addHeader(HttpHeaders.AUTHORIZATION, "Bearer " + sign(validClaims(), SECRET));

        filter.doFilter(request, response, chain);

        var authentication = SecurityContextHolder.getContext().getAuthentication();
        assertNotNull(authentication);
        assertEquals("user@example.com", authentication.getName());
        assertTrue(authentication.isAuthenticated());
        assertTrue(authentication.getAuthorities().isEmpty());
        assertNull(authentication.getCredentials());
        assertSame(request, chain.getRequest());
    }

    @Test
    void missingTokenContinuesWithoutAuthentication() throws Exception {
        filter.doFilter(request, response, chain);

        assertNull(SecurityContextHolder.getContext().getAuthentication());
        assertSame(request, chain.getRequest());
    }

    @Test
    void otherAuthenticationSchemeContinuesWithoutAuthentication() throws Exception {
        request.addHeader(HttpHeaders.AUTHORIZATION, "Basic dXNlcjpwYXNz");

        filter.doFilter(request, response, chain);

        assertNull(SecurityContextHolder.getContext().getAuthentication());
        assertSame(request, chain.getRequest());
    }

    @Test
    void bearerSchemeIsCaseInsensitive() throws Exception {
        request.addHeader(HttpHeaders.AUTHORIZATION, "bearer " + sign(validClaims(), SECRET));

        filter.doFilter(request, response, chain);

        assertNotNull(SecurityContextHolder.getContext().getAuthentication());
        assertSame(request, chain.getRequest());
    }

    @Test
    void expiredTokenIsRejected() throws Exception {
        assertRejected(sign(validClaims().expirationTime(
                java.util.Date.from(Instant.now().minusSeconds(120))), SECRET));
    }

    @Test
    void tokenNotYetValidIsRejected() throws Exception {
        assertRejected(sign(validClaims().notBeforeTime(
                java.util.Date.from(Instant.now().plusSeconds(60))), SECRET));
    }

    @Test
    void signatureFromAnotherKeyIsRejected() throws Exception {
        assertRejected(sign(validClaims(), "a-different-secret-with-at-least-32-bytes"));
    }

    @Test
    void tokenWithoutExpirationIsRejected() throws Exception {
        assertRejected(sign(new JWTClaimsSet.Builder().subject("user@example.com"), SECRET));
    }

    @Test
    void tokenWithoutSubjectIsRejected() throws Exception {
        assertRejected(sign(validClaims().subject(null), SECRET));
    }

    @Test
    void tokenWithBlankSubjectIsRejected() throws Exception {
        assertRejected(sign(validClaims().subject(" "), SECRET));
    }

    @Test
    void malformedTokenIsRejected() throws Exception {
        assertRejected("not-a-jwt");
    }

    @Test
    void emptyBearerTokenIsRejected() throws Exception {
        assertRejected("");
    }

    @Test
    void existingAuthenticationIsPreserved() throws Exception {
        var existing = UsernamePasswordAuthenticationToken.authenticated("existing", null, List.of());
        SecurityContextHolder.getContext().setAuthentication(existing);
        request.addHeader(HttpHeaders.AUTHORIZATION, "Bearer " + sign(validClaims(), SECRET));

        filter.doFilter(request, response, chain);

        assertSame(existing, SecurityContextHolder.getContext().getAuthentication());
        assertSame(request, chain.getRequest());
    }

    @Test
    void downstreamErrorsAreNotReportedAsInvalidTokens() throws Exception {
        request.addHeader(HttpHeaders.AUTHORIZATION, "Bearer " + sign(validClaims(), SECRET));
        IOException failure = new IOException("Downstream failure");

        IOException thrown = assertThrows(IOException.class,
                () -> filter.doFilter(request, response, (req, res) -> { throw failure; }));

        assertSame(failure, thrown);
        assertEquals(200, response.getStatus());
    }

    @Test
    void weakSecretIsRejectedAtStartup() {
        assertThrows(IllegalArgumentException.class,
                () -> new JwtAuthenticationFilter(new JwtProperties("short", 900000, 604800000)));
    }

    private JWTClaimsSet.Builder validClaims() {
        return new JWTClaimsSet.Builder()
                .subject("user@example.com")
                .issueTime(java.util.Date.from(Instant.now().minusSeconds(10)))
                .expirationTime(java.util.Date.from(Instant.now().plusSeconds(300)));
    }

    private String sign(JWTClaimsSet.Builder claims, String secret) throws Exception {
        SignedJWT token = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.HS256).type(JOSEObjectType.JWT).build(), claims.build());
        token.sign(new MACSigner(secret.getBytes(StandardCharsets.UTF_8)));
        return token.serialize();
    }

    private void assertRejected(String token) throws Exception {
        request.addHeader(HttpHeaders.AUTHORIZATION, "Bearer " + token);

        filter.doFilter(request, response, chain);

        assertEquals(401, response.getStatus());
        assertEquals("Bearer error=\"invalid_token\"", response.getHeader(HttpHeaders.WWW_AUTHENTICATE));
        assertNull(SecurityContextHolder.getContext().getAuthentication());
        assertNull(chain.getRequest());
    }
}
