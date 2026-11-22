package project.backend.security;

import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.Test;

import project.backend.config.JwtProperties;
import project.backend.domain.User;
import project.backend.services.JwtService;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class JwtServiceTests {

    private static final String SECRET = "test-secret-with-at-least-32-bytes-long";
    private final JwtService service = new JwtService(new JwtProperties(SECRET, 900000, 604800000));

    @Test
    void accessTokenContainsIdentityAndConfiguredLifetimeWithoutPassword() {
        User user = User.builder().id(UUID.randomUUID()).email("user@example.com")
                .passwordHash("must-not-be-in-token").build();

        var claims = service.parseToken(service.generateAccessToken(user));

        assertEquals(user.getEmail(), claims.getSubject());
        assertEquals(user.getId().toString(), claims.get("userId", String.class));
        assertEquals(900000, claims.getExpiration().getTime() - claims.getIssuedAt().getTime());
        assertFalse(claims.containsKey("passwordHash"));
        assertFalse(claims.containsValue(user.getPasswordHash()));
    }

    @Test
    void generatedAccessTokenIsValid() {
        assertTrue(service.isTokenValid(service.generateAccessToken(
                User.builder().id(UUID.randomUUID()).email("user@example.com").build())));
    }

    @Test
    void expiredTokenIsRejected() {
        String token = signedToken("user@example.com", Instant.now().minusSeconds(60), null);

        assertThrows(JwtException.class, () -> service.parseToken(token));
        assertFalse(service.isTokenValid(token));
    }

    @Test
    void tokenNotYetValidIsRejected() {
        assertFalse(service.isTokenValid(signedToken("user@example.com",
                Instant.now().plusSeconds(300), Instant.now().plusSeconds(60))));
    }

    @Test
    void signatureFromAnotherKeyIsRejected() {
        JwtService other = new JwtService(new JwtProperties(
                "another-secret-with-at-least-32-bytes-long", 900000, 604800000));
        String token = other.generateAccessToken(
                User.builder().id(UUID.randomUUID()).email("user@example.com").build());

        assertFalse(service.isTokenValid(token));
    }

    @Test
    void missingRequiredClaimsAreRejected() {
        assertFalse(service.isTokenValid(signedToken("user@example.com", null, null)));
        assertFalse(service.isTokenValid(signedToken(null, Instant.now().plusSeconds(300), null)));
        assertFalse(service.isTokenValid(signedToken(" ", Instant.now().plusSeconds(300), null)));
    }

    @Test
    void blankAndMalformedTokensAreInvalid() {
        assertFalse(service.isTokenValid(null));
        assertFalse(service.isTokenValid(" "));
        assertFalse(service.isTokenValid("not-a-jwt"));
    }

    @Test
    void unsignedTokensAreRejected() {
        String token = Jwts.builder().subject("user@example.com")
                .expiration(Date.from(Instant.now().plusSeconds(300))).compact();

        assertFalse(service.isTokenValid(token));
    }

    @Test
    void otherSigningAlgorithmsAreRejectedEvenWithTheSameSecret() {
        String longSecret = "a".repeat(64);
        JwtService longKeyService = new JwtService(new JwtProperties(longSecret, 900000, 604800000));
        String token = Jwts.builder().subject("user@example.com")
                .expiration(Date.from(Instant.now().plusSeconds(300)))
                .signWith(Keys.hmacShaKeyFor(longSecret.getBytes(StandardCharsets.UTF_8)), Jwts.SIG.HS512)
                .compact();

        assertFalse(longKeyService.isTokenValid(token));
    }

    @Test
    void refreshTokensAreUniqueAndCannotBeUsedAsAccessTokens() {
        String token = service.generateRefreshToken();

        assertNotEquals(token, service.generateRefreshToken());
        assertFalse(service.isTokenValid(token));
    }

    @Test
    void refreshTokenHashMatchesKnownSha256Value() {
        assertEquals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                service.hashRefreshToken("abc"));
        assertThrows(IllegalArgumentException.class, () -> service.hashRefreshToken(" "));
    }

    @Test
    void refreshExpirationUsesConfiguredLifetime() {
        Instant before = Instant.now().plusMillis(604800000);
        Instant expiration = service.refreshTokenExpiresAt();
        Instant after = Instant.now().plusMillis(604800000);

        assertFalse(expiration.isBefore(before));
        assertFalse(expiration.isAfter(after));
    }

    @Test
    void invalidConfigurationIsRejectedAtStartup() {
        assertThrows(IllegalArgumentException.class,
                () -> new JwtService(new JwtProperties(" ", 900000, 604800000)));
        assertThrows(IllegalArgumentException.class,
                () -> new JwtService(new JwtProperties("short", 900000, 604800000)));
        assertThrows(IllegalArgumentException.class,
                () -> new JwtService(new JwtProperties(SECRET, 0, 604800000)));
        assertThrows(IllegalArgumentException.class,
                () -> new JwtService(new JwtProperties(SECRET, 900000, 0)));
    }

    @Test
    void incompleteUserCannotReceiveToken() {
        assertThrows(IllegalArgumentException.class, () -> service.generateAccessToken(null));
        assertThrows(IllegalArgumentException.class,
                () -> service.generateAccessToken(User.builder().email("user@example.com").build()));
        assertThrows(IllegalArgumentException.class,
                () -> service.generateAccessToken(User.builder().id(UUID.randomUUID()).build()));
    }

    private String signedToken(String subject, Instant expiration, Instant notBefore) {
        return Jwts.builder().subject(subject)
                .expiration(expiration == null ? null : Date.from(expiration))
                .notBefore(notBefore == null ? null : Date.from(notBefore))
                .signWith(Keys.hmacShaKeyFor(SECRET.getBytes(StandardCharsets.UTF_8)), Jwts.SIG.HS256)
                .compact();
    }
}
