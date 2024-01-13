package com.gl.springsecuritywithjwt;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Data;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.Set;

@SpringBootApplication
public class SpringSecurityWithJwtApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringSecurityWithJwtApplication.class, args);
    }

}

@RestController
class ApplicationController {

    @Autowired
    private UserInfoRepo repo;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private AuthenticationManager authenticationManager;


    @PreAuthorize("hasRole('USER')")
    @GetMapping("/users/{username}")
    public Optional<UserInfo> getOneUserInfo(@PathVariable String username) {
        return repo.findById(username);
    }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/users")
    public List<UserInfo> getAllUserInfo() {
        return repo.findAll();
    }

    @PostMapping("/register")
    public UserInfo register(@RequestBody UserInfo userInfo) {
        if (userInfo.getRoles() == null) {
            userInfo.setRoles(Set.of("USER"));
        }
        userInfo.setPassword(passwordEncoder.encode(userInfo.getPassword()));
        return repo.save(userInfo);
    }

    @PostMapping("/token")
    public ResponseToken token(@RequestBody UserInfo userInfo) {
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(userInfo.getUsername(), userInfo.getPassword()));
            return ResponseToken.ok(
                    JwtUtil.generateAccessToken(userInfo.getUsername()),
                    JwtUtil.generateRefreshToken(userInfo.getUsername())
            );
        } catch (Exception exception) {
            return ResponseToken.error(exception.getMessage());
        }
    }

    @GetMapping("/refreshToken")
    public ResponseToken accessTokenFromRefreshToken(@RequestParam String refreshToken) {
        try {
            String username = JwtUtil.getUsernameFromRefreshToken(refreshToken);
            return ResponseToken.ok(
                    JwtUtil.generateAccessToken(username),
                    refreshToken
            );
        } catch (Exception exception) {
            return ResponseToken.error(exception.getMessage());
        }
    }

    @PreAuthorize("hasRole('ADMIN')")
    @DeleteMapping("/users/{username}")
    public void delete(@PathVariable String username) {
        repo.deleteById(username);
    }

    @GetMapping("/")
    public String all() {
        return "It is for all";
    }
}

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
class SpringSecurityConfig {

    @Autowired
    private JwtAuthFilter jwtAuthFilter;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .cors(AbstractHttpConfigurer::disable)
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(request -> request
                        .requestMatchers("/register", "/token", "/refreshToken", "/").permitAll()
                        .anyRequest().authenticated()
                )
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
                .build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        var authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(userDetailsService());
        authenticationProvider.setPasswordEncoder(passwordEncoder());
        return authenticationProvider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        return new UserDetailsServiceImpl();
    }
}

@Component
class JwtAuthFilter extends OncePerRequestFilter {

    @Autowired
    private UserDetailsServiceImpl userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String authorizationHeader = request.getHeader("Authorization");
        if (authorizationHeader == null) {
            filterChain.doFilter(request, response);
            return;
        }
        try {
            String token = authorizationHeader.substring("Bearer ".length());
            String username = JwtUtil.getUsername(token);
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);
            SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(username, null, userDetails.getAuthorities()));
        } catch (Exception exception) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write(exception.getMessage());
            response.getWriter().flush();
            return;
        }

        filterChain.doFilter(request, response);

    }
}

@Component
class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    private UserInfoRepo repo;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<UserInfo> userInfoOptional = repo.findById(username);
        if (userInfoOptional.isPresent()) {
            UserInfo userInfo = userInfoOptional.get();
            return User.builder()
                    .username(userInfo.getUsername())
                    .password(userInfo.getPassword())
                    .roles(userInfo.getRoles().toArray(String[]::new))
                    .build();
        } else {
            throw new UsernameNotFoundException("username: " + username + " not found");
        }

    }
}

class JwtUtil {
    public static String generateAccessToken(String username) {
        return Jwts.builder()
                .claim("username", username)
                .issuedAt(new Date(Instant.now().toEpochMilli()))
                .expiration(new Date(Instant.now().plus(1, ChronoUnit.DAYS).toEpochMilli()))
                .signWith(getKey())
                .compact();
    }

    public static String generateRefreshToken(String username) {
        return Jwts.builder()
                .claim("username", username)
                .issuedAt(new Date(Instant.now().toEpochMilli()))
                .expiration(new Date(Instant.now().plus(30, ChronoUnit.DAYS).toEpochMilli()))
                .signWith(getRefreshKey())
                .compact();
    }

    public static String getUsername(String token) {
        return (String) Jwts.parser()
                .verifyWith(getKey())
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .get("username");
    }

    public static String getUsernameFromRefreshToken(String refreshToken) {
        return (String) Jwts.parser()
                .verifyWith(getRefreshKey())
                .build()
                .parseSignedClaims(refreshToken)
                .getPayload()
                .get("username");
    }


    private static SecretKey getKey() {
        return Keys.hmacShaKeyFor(SECRET_KEY.getBytes(StandardCharsets.UTF_8));
    }

    private static SecretKey getRefreshKey() {
        return Keys.hmacShaKeyFor(REFRESH_SECRET_KEY.getBytes(StandardCharsets.UTF_8));
    }

    private static final String SECRET_KEY = "as45fg6y7hh7shrimp8923fdf34fg45fg45ht4rg4e34ef";
    private static final String REFRESH_SECRET_KEY = "45545y7hh7shr4545df344st445fg467676ht4rg4e34ef";
}

interface UserInfoRepo extends JpaRepository<UserInfo, String> {
}

@Data
class ResponseToken {
    private String accessToken;
    private String refreshToken;
    private String error;

    private ResponseToken() {
    }

    private ResponseToken(String accessToken, String refreshToken) {
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
    }

    private ResponseToken(String error) {
        this.error = error;
    }

    public static ResponseToken ok(String accessToken, String refreshToken) {
        return new ResponseToken(accessToken, refreshToken);
    }

    public static ResponseToken error(String error) {
        return new ResponseToken(error);
    }
}

@Data
@Entity
class UserInfo {
    @Id
    private String username;
    private String password;
    private Set<String> roles;
}
