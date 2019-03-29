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
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cloud.stream.annotation.EnableBinding;
import org.springframework.cloud.stream.annotation.StreamListener;
import org.springframework.cloud.stream.messaging.Sink;
import org.springframework.cloud.stream.messaging.Source;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.messaging.support.MessageBuilder;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import javax.validation.constraints.NotEmpty;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;

@EnableConfigurationProperties
@SpringBootApplication
public class Application {
    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }
}

@RestController
@RequestMapping
@EnableBinding({Sink.class, Source.class})
@RequiredArgsConstructor
@Slf4j
class MessagesController {
    private final CopyOnWriteArrayList<SseEmitter> emitters = new CopyOnWriteArrayList<>();
    private final Source messageSource;
    private final UserIdentity user;

    @StreamListener(Sink.INPUT)
    void onNewMessage(Message msg) {
        // Listen to the topic where messages are sent to
        // by an app instance when an user posts something.
        log.debug("Received new message: {}", msg);

        List<SseEmitter> deadEmitters = null;
        for (final SseEmitter emitter : emitters) {
            try {
                log.trace("Sending message to client: {}", msg);
                emitter.send(msg, MediaType.APPLICATION_JSON);
            } catch (Exception e) {
                if (deadEmitters == null) {
                    deadEmitters = new ArrayList<>(1);
                }
                deadEmitters.add(emitter);
            }
        }
        if (deadEmitters != null) {
            emitters.removeAll(deadEmitters);
        }
    }

    @GetMapping(value = "/api/messages/sse")
    SseEmitter getMessageEvents() {
        // Get message stream using a HTML5 Server-Sent-Event endpoint.

        final SseEmitter emitter = new SseEmitter();
        emitters.add(emitter);
        emitter.onCompletion(() -> emitters.remove(emitter));
        emitter.onTimeout(() -> emitters.remove(emitter));

        return emitter;
    }

    @PostMapping("/api/messages")
    @PreAuthorize("isAuthenticated()")
    ResponseEntity<?> newMessage(@RequestParam("message") @NotEmpty String newMsg) {
        final String author = user.getUser();
        final String avatar = user.getAvatar();
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
    private final String avatar;

    static Message from(String msg, String author, String avatar) {
        return new Message(
                UUID.randomUUID(),
                msg, ZonedDateTime.now(), author, avatar);
    }
}
