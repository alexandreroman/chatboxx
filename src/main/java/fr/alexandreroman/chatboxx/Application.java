/*
 * Copyright (c) 2019 Pivotal Software, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package fr.alexandreroman.chatboxx;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso;
import org.springframework.cloud.stream.annotation.EnableBinding;
import org.springframework.cloud.stream.annotation.StreamListener;
import org.springframework.cloud.stream.messaging.Sink;
import org.springframework.cloud.stream.messaging.Source;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.lang.Nullable;
import org.springframework.messaging.support.MessageBuilder;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;
import org.springframework.web.util.UriComponentsBuilder;

import javax.validation.constraints.NotEmpty;
import java.io.IOException;
import java.net.URL;
import java.time.ZonedDateTime;
import java.util.Map;
import java.util.UUID;

@SpringBootApplication
public class Application {
    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }
}

@RestController
@RequestMapping(path = "/api")
@EnableBinding({Sink.class, Source.class})
@RequiredArgsConstructor
@Slf4j
class MessagesController {
    private final SseEmitter sseEmitter = new SseEmitter(0L);
    private final Source messageSource;

    @StreamListener(Sink.INPUT)
    void onNewMessage(Message msg) throws IOException {
        // Listen to the topic where messages are sent to
        // by an app instance when an user posts something.
        log.debug("Received new message: {}", msg);
        sseEmitter.send(msg);
    }

    @GetMapping("/messages/sse")
    SseEmitter getMessageEvents() {
        // Get message stream using a HTML5 Server-Sent-Event endpoint.
        return sseEmitter;
    }

    @PostMapping("/messages")
    ResponseEntity<?> newMessage(@RequestParam("message") @NotEmpty String newMsg) {
        // TODO get user identity
        final String author = "Someone";
        final URL avatar = null;
        final Message msg = Message.from(newMsg, author, avatar);

        // Publish this message to all app instances.
        log.info("New message posted: {}", msg);
        messageSource.output().send(MessageBuilder.withPayload(msg).build());

        // Since we are a good REST citizen, the message is returned as a result.
        return ResponseEntity.ok(msg);
    }
}

@Data
@JsonInclude(JsonInclude.Include.NON_EMPTY)
class Message {
    private final UUID id;
    private final String message;
    private final ZonedDateTime timeCreated;
    private final String author;
    private final URL avatar;

    static Message from(String msg, String author, URL avatar) {
        return new Message(
                UUID.randomUUID(),
                msg, ZonedDateTime.now(), author, avatar);
    }
}

@Controller
@RequiredArgsConstructor
class LoginController {
    @GetMapping("/login")
    ResponseEntity<?> login(UriComponentsBuilder ucb) {
        // User login is managed by Spring Security:
        // here we just redirect the request to the home page
        // AFTER a successful user authentication.

        return ResponseEntity.status(HttpStatus.TEMPORARY_REDIRECT)
                .location(ucb.path("/").build().toUri()).build();
    }

    // TODO add logout
}

@RestController
@RequiredArgsConstructor
class IdentityController {
    private final IdentityProvider identityProvider;

    @GetMapping("/api/me")
    ResponseEntity<?> me() {
        final Identity id = identityProvider.getIdentity();
        if (id == null) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body("You're not authenticated");
        }
        return ResponseEntity.ok(id);
    }
}

@Data
@JsonInclude(JsonInclude.Include.NON_EMPTY)
class Identity {
    private final String user;
    @Nullable
    private final String avatar;
}

/**
 * User identity provider.
 */
interface IdentityProvider {
    /**
     * Get current authenticated user identity, if any.
     *
     * @return user identity, <code>null</code> if there is no authenticated user
     */
    @Nullable
    Identity getIdentity();
}

@EnableOAuth2Sso
@Configuration
class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.antMatcher("/**")
                .authorizeRequests()
                .antMatchers("/actuator**", "/logout", "/error**", "/api/me", "/", "/index.html", "**.js", "**.css", "**.png", "**.ico").permitAll()
                .anyRequest().authenticated();
    }

    @Bean
    @Profile("!noauth")
    IdentityProvider identityProvider() {
        return () -> {
            final Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            if (auth == null || !(auth instanceof OAuth2Authentication)) {
                return null;
            }

            // Use Spring Security OAuth2 support to get user identity.
            final OAuth2Authentication oauth2 = (OAuth2Authentication) auth;
            if (!(oauth2.getUserAuthentication() instanceof UsernamePasswordAuthenticationToken)) {
                return null;
            }

            final UsernamePasswordAuthenticationToken userToken = (UsernamePasswordAuthenticationToken) oauth2.getUserAuthentication();
            final Map<String, Object> userDetails = (Map<String, Object>) userToken.getDetails();

            // Extract user details.
            final String userAvatar = (String) userDetails.get("avatar_url");
            final String userId = userToken.getName();
            return new Identity(userId, userAvatar);
        };
    }

    @Bean
    @Profile("noauth")
    IdentityProvider dummyIdentityProvider() {
        // Return a default user identity.
        return () -> new Identity("johndoe", null);
    }
}
