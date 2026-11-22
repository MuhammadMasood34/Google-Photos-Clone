package project.backend;

import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.client.RestClient;
import org.springframework.web.context.WebApplicationContext;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class BackendApplicationTests {
    private static final String REGISTER_PATH = "/api/auth/register";

    @LocalServerPort
    private int port;

    @Autowired
    private WebApplicationContext context;

    @Test
    void registerRejectsGetWithMethodNotAllowed() {
        RestClient client = RestClient.create("http://localhost:" + port);

        client.get().uri(REGISTER_PATH).exchange((request, response) -> {
            assertEquals(HttpStatus.METHOD_NOT_ALLOWED, response.getStatusCode());
            assertEquals("POST", response.getHeaders().getFirst("Allow"));
            return null;
        });
    }

    @Test
    void registerReturnsRequestValidationErrors() {
        RestClient client = RestClient.create("http://localhost:" + port);

        assertEquals(HttpStatus.UNSUPPORTED_MEDIA_TYPE, client.post().uri(REGISTER_PATH)
                .contentType(MediaType.TEXT_PLAIN).body("{}")
                .exchange((request, response) -> response.getStatusCode()));
        assertEquals(HttpStatus.BAD_REQUEST, client.post().uri(REGISTER_PATH)
                .contentType(MediaType.APPLICATION_JSON).body("{}")
                .exchange((request, response) -> response.getStatusCode()));
        assertEquals(HttpStatus.UNAUTHORIZED, client.get().uri("/api/auth/me")
                .exchange((request, response) -> response.getStatusCode()));
    }

    @Test
    @Transactional
    void registerAcceptsJsonWithoutAuthorization() throws Exception {
        String email = "registration-" + UUID.randomUUID() + "@example.com";
        MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build()
                .perform(post(REGISTER_PATH).contentType(MediaType.APPLICATION_JSON).content("""
                        {"email":"%s","password":"LocalTest123!","displayName":"Suraj"}
                        """.formatted(email)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.user.email").value(email));
    }
}
