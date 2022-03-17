package org.camunda.example.filter.rest;

import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;

@Configuration
@Order(SecurityProperties.BASIC_AUTH_ORDER - 20)
public class RestSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .antMatcher("/engine-rest/**")
                .authorizeRequests().anyRequest().authenticated()
                .and()
                .csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .httpBasic();
//                .authenticationEntryPoint(authenticationEntryPoint());
    }

/*    @Bean
    public AuthenticationEntryPoint authenticationEntryPoint() {
        var entryPoint = new RestAuthenticationEntryPoint();
        entryPoint.setRealmName("camunda-auth");
        return entryPoint;
    }*/


    @SuppressWarnings("rawtypes")
    @Bean
    public FilterRegistrationBean statelessUserAuthenticationFilter() {
        FilterRegistrationBean filterRegistration = new FilterRegistrationBean();
        filterRegistration.setFilter(new StatelessUserAuthenticationFilter());
        filterRegistration.setOrder(102); // ensure  filter is registered after the Spring Security Filter Chain
        filterRegistration.addUrlPatterns("/engine-rest/*");
        return filterRegistration;
    }

 /*   @Bean
    public FilterRegistrationBean processEngineAuthenticationFilter() {
        FilterRegistrationBean registration = new FilterRegistrationBean();
        registration.setName("camunda-auth");
        registration.setFilter(getProcessEngineAuthenticationFilter());
        registration.addInitParameter("authentication-provider",
                "org.camunda.bpm.engine.rest.security.auth.impl.HttpBasicAuthenticationProvider");
        registration.addUrlPatterns("/*");
        return registration;
    }

    @Bean
    public Filter getProcessEngineAuthenticationFilter() {
        return new ProcessEngineAuthenticationFilter();
    }*/
}
