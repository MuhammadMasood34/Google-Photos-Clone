package project.backend.services;

import java.nio.charset.StandardCharsets;
import java.sql.SQLException;
import java.time.Instant;
import java.util.Locale;

import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ResponseStatusException;

import project.backend.domain.RefreshToken;
import project.backend.domain.User;
import project.backend.dto.AuthResponse;
import project.backend.dto.LoginRequest;
import project.backend.dto.RefreshTokenRequest;
import project.backend.dto.RegisterRequest;
import project.backend.exception.ResourceConflictException;
import project.backend.exception.UnauthorizedException;
import project.backend.repository.RefreshTokenRepository;
import project.backend.repository.UserRepository;

@Service
public class AuthService {

    private static final int BCRYPT_MAX_PASSWORD_BYTES = 72;
    private static final String EMAIL_ALREADY_REGISTERED = "Email is already registered";
    private static final String INVALID_CREDENTIALS = "Invalid email or password";
    private static final String INVALID_REFRESH_TOKEN = "Invalid or expired refresh token";

    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final UserService userService;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;

    public AuthService(
            UserRepository userRepository,
            RefreshTokenRepository refreshTokenRepository,
            UserService userService,
            PasswordEncoder passwordEncoder,
            AuthenticationManager authenticationManager,
            JwtService jwtService) {
        this.userRepository = userRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.userService = userService;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;
    }

    @Transactional
    public AuthResponse register(RegisterRequest request) {
        String email = normalizeEmail(request.email());
        if (userRepository.existsByEmail(email)) {
            throw new ResourceConflictException(EMAIL_ALREADY_REGISTERED);
        }
        if (exceedsBcryptLimit(request.password())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Password must be at most 72 UTF-8 bytes");
        }

        User user = User.builder()
                .email(email)
                .passwordHash(passwordEncoder.encode(request.password()))
                .displayName(request.displayName().trim())
                .build();

        try {
            user = userRepository.saveAndFlush(user);
        } catch (DataIntegrityViolationException exception) {
            // PostgreSQL reports a unique violation if another request registered this email first.
            if (exception.getMostSpecificCause() instanceof SQLException cause && "23505".equals(cause.getSQLState())) {
                throw new ResourceConflictException(EMAIL_ALREADY_REGISTERED, exception);
            }
            throw exception;
        }
        return buildAuthResponse(user);
    }

    @Transactional
    public AuthResponse login(LoginRequest request) {
        String email = normalizeEmail(request.email());
        if (exceedsBcryptLimit(request.password())) {
            throw new UnauthorizedException(INVALID_CREDENTIALS);
        }

        try {
            authenticationManager.authenticate(UsernamePasswordAuthenticationToken.unauthenticated(email, request.password()));
        } catch (BadCredentialsException exception) {
            throw new UnauthorizedException(INVALID_CREDENTIALS);
        }
        User user = userService.getByEmail(email);
        refreshTokenRepository.deleteByUser_Id(user.getId());
        return buildAuthResponse(user);
    }

    @Transactional
    public AuthResponse refresh(RefreshTokenRequest request) {
        String token = request.refreshToken();
        if (!StringUtils.hasText(token)) {
            throw new UnauthorizedException(INVALID_REFRESH_TOKEN);
        }

        RefreshToken storedToken = refreshTokenRepository.findByToken(jwtService.hashRefreshToken(token))
                .filter(refreshToken -> refreshToken.getExpiresAt().isAfter(Instant.now()))
                .orElseThrow(() -> new UnauthorizedException(INVALID_REFRESH_TOKEN));
        return buildAuthResponse(storedToken);
    }

    @Transactional
    public void logout(String email) {
        User user = userService.getByEmail(normalizeEmail(email));
        refreshTokenRepository.deleteByUser_Id(user.getId());
    }

    @Transactional
    public void logoutByRefreshToken(String token) {
        if (StringUtils.hasText(token)) {
            refreshTokenRepository.findByToken(jwtService.hashRefreshToken(token))
                    .ifPresent(refreshTokenRepository::delete);
        }
    }

    private AuthResponse buildAuthResponse(User user) {
        RefreshToken storedToken = RefreshToken.builder()
                .user(user)
                .build();
        return buildAuthResponse(storedToken);
    }

    private AuthResponse buildAuthResponse(RefreshToken storedToken) {
        User user = storedToken.getUser();
        String accessToken = jwtService.generateAccessToken(user);
        String refreshTokenValue = jwtService.generateRefreshToken();

        storedToken.setToken(jwtService.hashRefreshToken(refreshTokenValue));
        storedToken.setExpiresAt(jwtService.refreshTokenExpiresAt());
        refreshTokenRepository.save(storedToken);

        return new AuthResponse(
                accessToken,
                refreshTokenValue,
                userService.toUserResponse(user));
    }

    private static String normalizeEmail(String email) {
        return email.trim().toLowerCase(Locale.ROOT);
    }

    private static boolean exceedsBcryptLimit(String password) {
        return password.getBytes(StandardCharsets.UTF_8).length > BCRYPT_MAX_PASSWORD_BYTES;
    }
}
