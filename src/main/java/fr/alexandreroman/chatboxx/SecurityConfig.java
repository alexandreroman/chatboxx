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

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.*;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.UriComponentsBuilder;

import javax.security.auth.Subject;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.*;

@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true, proxyTargetClass = true)
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    private SecurityProps securityProps;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable();
        http.httpBasic().disable().formLogin().disable();
        http.exceptionHandling().accessDeniedHandler((req, resp, e) -> resp.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Access denied"))
                .authenticationEntryPoint((req, resp, e) -> resp.sendError(HttpServletResponse.SC_FORBIDDEN));
        http.anonymous();
        http.antMatcher("/**")
                .authorizeRequests()
                .antMatchers("/actuator**", "/error**", "/login**", "/login/oauth2/**", "/logout",
                        "/", "**.js", "**.css", "**.png", "**.ico").permitAll();
        http.oauth2Login().loginPage("/login")
                .and().logout().logoutSuccessUrl("/").permitAll();
        http.addFilterBefore(new JwtAuthenticationTokenFilter(securityProps), SecurityContextHolderAwareRequestFilter.class);
    }

    @Bean
    @Profile("!noauth")
    @Scope(value = WebApplicationContext.SCOPE_REQUEST, proxyMode = ScopedProxyMode.TARGET_CLASS)
    UserIdentity identityProvider() {
        final Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth instanceof OAuth2AuthenticationToken) {
            final OAuth2AuthenticationToken oauth2 = (OAuth2AuthenticationToken) auth;
            final OAuth2User user = oauth2.getPrincipal();
            return new UserIdentity((String) user.getAttributes().get("login"),
                    (String) user.getAttributes().get("html_url"),
                    (String) user.getAttributes().get("avatar_url"));
        }
        if (auth instanceof JwtAuthenticationToken) {
            final JwtAuthenticationToken jwt = (JwtAuthenticationToken) auth;
            return new UserIdentity(jwt.getUserId(), jwt.getUserProfile(), jwt.getUserAvatar());
        }
        throw new IllegalArgumentException("Unsupported authentication: " + auth);
    }

    @Bean
    @Profile("noauth")
    UserIdentity dummyIdentityProvider() {
        // Return a default user identity.
        return new UserIdentity("johndoe", "https://github.com/johndoe", null);
    }
}

@Data
@Component
@ConfigurationProperties(prefix = "security")
class SecurityProps {
    private long tokenLifetime = 604_800_000;
    private String tokenSecret = "ThisIsMySuperSecretTokenWhichNeedsToBeLongEnough";
}

@Controller
@RequiredArgsConstructor
class LoginController {
    @GetMapping("/login")
    ResponseEntity<?> login(UriComponentsBuilder ucb) {
        return ResponseEntity.status(HttpStatus.TEMPORARY_REDIRECT)
                .location(ucb.path("/oauth2/authorization/github").build().toUri()).build();
    }
}

@RestController
@RequiredArgsConstructor
class UserIdentityController {
    private final UserIdentity user;
    private final SecurityProps securityProps;

    @GetMapping("/api/me")
    @PreAuthorize("isAuthenticated()")
    ResponseEntity<?> me() {
        final Map<String, String> result = new HashMap<>(2);
        result.put("user", user.getUser());
        result.put("profile", user.getProfile());
        result.put("avatar", user.getAvatar());

        final String jwt = Jwts.builder()
                .setId(UUID.randomUUID().toString())
                .setSubject(user.getUser())
                .claim("profile", user.getProfile())
                .claim("avatar", user.getAvatar())
                .setExpiration(new Date(System.currentTimeMillis() + securityProps.getTokenLifetime()))
                .signWith(Keys.hmacShaKeyFor(securityProps.getTokenSecret().getBytes()), SignatureAlgorithm.HS256)
                .compact();

        return ResponseEntity.ok()
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + jwt)
                .header(HttpHeaders.ACCESS_CONTROL_EXPOSE_HEADERS, HttpHeaders.AUTHORIZATION)
                .header(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, "*")
                .body(result);
    }
}

@Data
class UserIdentity {
    private final String user;
    private final String profile;
    private final String avatar;
}

class JwtAuthenticationTokenFilter extends OncePerRequestFilter {
    private final SecurityProps securityProps;

    public JwtAuthenticationTokenFilter(
            final SecurityProps securityProps) {
        super();
        this.securityProps = securityProps;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse resp, FilterChain chain) throws IOException, ServletException {
        final String authToken = req.getHeader(HttpHeaders.AUTHORIZATION);
        if (authToken != null && authToken.startsWith("Bearer ")) {
            final String jwt = authToken.replaceFirst("Bearer ", "");

            final Claims jwtClaims = Jwts.parser()
                    .setSigningKey(Keys.hmacShaKeyFor(securityProps.getTokenSecret().getBytes()))
                    .parseClaimsJws(jwt).getBody();
            final String userId = jwtClaims.getSubject();
            final String userProfile = jwtClaims.get("profile", String.class);
            final String userAvatar = jwtClaims.get("avatar", String.class);

            SecurityContextHolder.getContext()
                    .setAuthentication(new JwtAuthenticationToken(userId, userProfile, userAvatar));
        }

        chain.doFilter(req, resp);
    }
}

class JwtAuthenticationToken extends UsernamePasswordAuthenticationToken {
    private final String userAvatar;
    private final String userProfile;

    JwtAuthenticationToken(final String userId, final String userProfile, final String userAvatar) {
        super(userId, null, Collections.emptyList());
        this.userProfile = userProfile;
        this.userAvatar = userAvatar;
    }

    public String getUserId() {
        return (String) getPrincipal();
    }

    public String getUserAvatar() {
        return userAvatar;
    }

    public String getUserProfile() {
        return userProfile;
    }

    @Override
    public boolean implies(Subject subject) {
        return false;
    }
}
