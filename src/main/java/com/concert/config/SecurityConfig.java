package com.concert.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.Collections;

/**
 * Spring Security Configuration.
 *
 * VULNERABILITIES DEMONSTRATED:
 * 1. CSRF protection disabled globally
 * 2. All endpoints permitted without authentication
 * 3. H2 console exposed with frame options disabled
 * 4. NoOpPasswordEncoder used (stores passwords in plain text)
 * 5. CORS configured to allow all origins, methods, and headers
 * 6. Debug/admin endpoints not protected
 * 7. HTTP (not HTTPS) not enforced
 * 8. Session fixation protection disabled
 * 9. Clickjacking protection (X-Frame-Options) disabled
 * 10. Content Security Policy not configured
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            // VULNERABILITY: CSRF protection completely disabled
            .csrf().disable()

            // VULNERABILITY: Clickjacking protection disabled (allows framing)
            .headers()
                .frameOptions().disable()
                .and()

            // VULNERABILITY: All requests permitted without any authentication
            .authorizeRequests()
                .antMatchers("/**").permitAll() // VULNERABILITY: Wildcard - everything is public
                .anyRequest().permitAll()
                .and()

            // VULNERABILITY: CORS allows all origins
            .cors()
                .and()

            // VULNERABILITY: Session fixation protection disabled
            .sessionManagement()
                .sessionFixation().none() // VULNERABILITY: No session fixation protection
                .and()

            // VULNERABILITY: No HTTPS enforcement
            // Should have: requiresChannel().anyRequest().requiresSecure()

            // VULNERABILITY: H2 console accessible to everyone
            .formLogin().disable()
            .httpBasic().disable();

        // NOTE: The following security headers are NOT configured (vulnerabilities):
        // - X-Content-Type-Options (MIME sniffing)
        // - X-XSS-Protection
        // - Strict-Transport-Security (HSTS)
        // - Content-Security-Policy
        // - Referrer-Policy
    }

    /**
     * VULNERABILITY: NoOpPasswordEncoder stores and compares passwords in plain text.
     * Should use BCryptPasswordEncoder with strength >= 12.
     */
    @Bean
    @SuppressWarnings("deprecation")
    public PasswordEncoder passwordEncoder() {
        // VULNERABILITY: Plain text password storage - no hashing at all
        return NoOpPasswordEncoder.getInstance();
    }

    /**
     * VULNERABILITY: CORS configured to allow:
     * - Any origin (*)
     * - Any HTTP method (GET, POST, PUT, DELETE, OPTIONS, PATCH)
     * - Any header
     * - Credentials allowed with wildcard origin (security misconfiguration)
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();

        // VULNERABILITY: Allows requests from any origin
        configuration.setAllowedOriginPatterns(Collections.singletonList("*"));

        // VULNERABILITY: Allows all HTTP methods including DELETE, PUT
        configuration.setAllowedMethods(Arrays.asList(
                "GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH", "HEAD"
        ));

        // VULNERABILITY: Allows all headers (including custom auth headers)
        configuration.setAllowedHeaders(Collections.singletonList("*"));

        // VULNERABILITY: Allows credentials with wildcard origin
        configuration.setAllowCredentials(true);

        // VULNERABILITY: Long preflight cache (1 hour)
        configuration.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}

// Made with Bob
