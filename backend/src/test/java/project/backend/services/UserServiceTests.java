package project.backend.services;

import java.util.Locale;
import java.util.Optional;
import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.ResourceLock;

import project.backend.domain.User;
import project.backend.exception.UnauthorizedException;
import project.backend.repository.UserRepository;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class UserServiceTests {

    private final UserRepository repository = mock(UserRepository.class);
    private final UserService service = new UserService(repository);

    @Test
    @ResourceLock("default-locale")
    void emailLookupUsesLocaleIndependentLowercase() {
        Locale previous = Locale.getDefault();
        try {
            Locale.setDefault(Locale.forLanguageTag("tr-TR"));
            User user = User.builder().email("ilker@example.com").build();
            when(repository.findByEmail("ilker@example.com")).thenReturn(Optional.of(user));

            assertSame(user, service.getByEmail("ILKER@EXAMPLE.COM"));
        } finally {
            Locale.setDefault(previous);
        }
    }

    @Test
    void missingUserThrowsUnauthorizedException() {
        when(repository.findByEmail("missing@example.com")).thenReturn(Optional.empty());

        var exception = assertThrows(UnauthorizedException.class,
                () -> service.getByEmail("missing@example.com"));

        assertEquals("User not found", exception.getMessage());
    }

    @Test
    void responseContainsPublicUserDetails() {
        User user = User.builder().id(UUID.randomUUID()).email("user@example.com")
                .displayName("Masood").passwordHash("private-password-hash").build();
        when(repository.findByEmail(user.getEmail())).thenReturn(Optional.of(user));

        var response = service.getUserResponseByEmail(user.getEmail());

        assertEquals(user.getId(), response.id());
        assertEquals(user.getEmail(), response.email());
        assertEquals(user.getDisplayName(), response.displayName());
    }

    @Test
    void emailLookupByIdReturnsEmailWhenUserExists() {
        UUID id = UUID.randomUUID();
        when(repository.findById(id)).thenReturn(Optional.of(
                User.builder().id(id).email("user@example.com").build()));

        assertEquals(Optional.of("user@example.com"), service.findEmailById(id));
    }

    @Test
    void emailLookupByIdIsEmptyWhenUserDoesNotExist() {
        UUID id = UUID.randomUUID();
        when(repository.findById(id)).thenReturn(Optional.empty());

        assertTrue(service.findEmailById(id).isEmpty());
    }
}
