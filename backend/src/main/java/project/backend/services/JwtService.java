//provides the token helpers ,refresh endpoint and and database checks
package project.backend.services;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import project.backend.config.JwtProperties;
import project.backend.domain.User;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Date;
import java.util.HexFormat;
import java.util.UUID;

/**
 * Creates access tokens and provides helpers for managing opaque refresh
 * tokens.
 */
@Service
public class JwtService {

    private final JwtProperties jwtProperties;
    private final SecretKey secretKey;

    public JwtService(JwtProperties jwtProperties) {
        Assert.notNull(jwtProperties, "JWT properties must not be null");
        Assert.hasText(jwtProperties.secret(), "app.jwt.secret must not be blank");
        Assert.isTrue(jwtProperties.accessExpirationMs() >= 1000,
                "app.jwt.access-expiration-ms must be at least 1000 (one second)");
        Assert.isTrue(jwtProperties.refreshExpirationMs() > 0,
                "app.jwt.refresh-expiration-ms must be positive");

        byte[] secret = jwtProperties.secret().getBytes(StandardCharsets.UTF_8);
        Assert.isTrue(secret.length >= 32, "app.jwt.secret must contain at least 32 UTF-8 bytes");
        this.jwtProperties = jwtProperties;
        this.secretKey = Keys.hmacShaKeyFor(secret);
    }

    public String generateAccessToken(User user) {
        Assert.notNull(user, "User must not be null");
        Assert.notNull(user.getId(), "User must have an ID before issuing a token");
        Assert.hasText(user.getEmail(), "User email must not be blank");

        Instant now = Instant.now();
        return Jwts.builder()
                .subject(user.getEmail())
                .claim("userId", user.getId().toString())
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusMillis(jwtProperties.accessExpirationMs())))
                // Keep the algorithm compatible with JwtAuthenticationFilter.
                .signWith(secretKey, Jwts.SIG.HS256)
                .compact();
    }

    /** Verifies the signature and timestamps before returning trusted claims. */
    public Claims parseToken(String token) {
        Assert.hasText(token, "Token must not be blank");
        var signedClaims = Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token);
        if (!Jwts.SIG.HS256.getId().equals(signedClaims.getHeader().getAlgorithm())) {
            throw new UnsupportedJwtException("Only HS256 access tokens are supported");
        }
        Claims claims = signedClaims.getPayload();

        if (!StringUtils.hasText(claims.getSubject()) || claims.getExpiration() == null) {
            throw new MalformedJwtException("JWT must contain a subject and expiration");
        }
        return claims;
    }

    public boolean isTokenValid(String token) {
        try {
            parseToken(token);
            return true;
        } catch (JwtException | IllegalArgumentException exception) {
            return false;
        }
    }

    /**
     * Refresh tokens are random credentials, not JWTs accepted by the request
     * filter.
     */
    public String generateRefreshToken() {
        return UUID.randomUUID().toString() + UUID.randomUUID();
    }

    /**
     * Store this hash in RefreshToken.token; return only the original token to the
     * client.
     */
    public String hashRefreshToken(String token) {
        Assert.hasText(token, "Refresh token must not be blank");
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256")
                    .digest(token.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
    }

    public Instant refreshTokenExpiresAt() {
        return Instant.now().plusMillis(jwtProperties.refreshExpirationMs());
    }
}
