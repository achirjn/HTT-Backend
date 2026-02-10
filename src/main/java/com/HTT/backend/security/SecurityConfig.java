package com.HTT.backend.security;

import java.util.Arrays;
import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import static org.springframework.security.config.Customizer.withDefaults;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
public class SecurityConfig {

    private final OAuthSuccessHandler oAuthSuccessHandler;

    public SecurityConfig(OAuthSuccessHandler oAuthSuccessHandler) {
        this.oAuthSuccessHandler = oAuthSuccessHandler;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{
        http
            .cors(withDefaults())
            .authorizeHttpRequests(auth -> auth
                // .requestMatchers("/api/admin/**").hasRole("ADMIN")
                // .requestMatchers("/login/oauth2/**").permitAll()
                // .anyRequest().permitAll()
                .anyRequest().authenticated()
                );
        http.oauth2Login(oauth -> {
            // oauth.loginPage("https://www.thinkindiasvnit.in/login");
            oauth.successHandler(oAuthSuccessHandler);
        });
        return http.build();
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        
        // This is the origin of your React app
        configuration.setAllowedOrigins(Arrays.asList("http://localhost:8082")); 
        
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(List.of("Authorization", "Content-Type"));
        configuration.setExposedHeaders(List.of("Authorization"));
        
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        
        return source;
    }
}
