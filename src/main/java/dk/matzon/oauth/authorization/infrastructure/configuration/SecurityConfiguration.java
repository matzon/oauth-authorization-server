package dk.matzon.oauth.authorization.infrastructure.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {

    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests((authz) -> authz
                        .anyRequest().authenticated()
                )
                .formLogin(withDefaults());
        return http.build();
    }

    @Bean
    protected InMemoryUserDetailsManager userDetailsService() throws Exception {

        UserDetails admin = User.withUsername("admin")
                .password("{noop}admin")
                .roles("admin")
                .authorities("read", "write")
                .build();

        UserDetails joe = User.withUsername("joe")
                .password("{noop}joe")
                .roles("user")
                .authorities("read")
                .build();

        return new InMemoryUserDetailsManager(admin, joe);
    }
}
