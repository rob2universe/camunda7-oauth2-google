package org.camunda.example.oauth2;

import org.camunda.bpm.webapp.impl.security.auth.ContainerBasedAuthenticationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

import java.util.Collections;

@Configuration
@Order(SecurityProperties.BASIC_AUTH_ORDER - 15)
public class WebAppSecurityConfig extends WebSecurityConfigurerAdapter {

  @Autowired
  private GoogleOAuth2UserService oauthUserService;

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http
        .csrf().disable()
        .antMatcher("/**")
        .authorizeRequests().anyRequest().authenticated()
        .and()
        .oauth2Login()
            // use own service to create principal
            .userInfoEndpoint().userService(oauthUserService)
//        .and()
//        .successHandler(new CamundaAuthenticationSuccessHandler())
    ;
  }

  @Bean
  public FilterRegistrationBean containerBasedAuthenticationFilter() {

    FilterRegistrationBean filterRegistration = new FilterRegistrationBean();
    filterRegistration.setFilter(new ContainerBasedAuthenticationFilter());
    filterRegistration.setInitParameters(Collections.singletonMap("authentication-provider", "org.camunda.example.filter.webapp.SpringSecurityAuthenticationProvider"));
    filterRegistration.setOrder(101); // make sure the filter is registered after the Spring Security Filter Chain
    filterRegistration.addUrlPatterns("/camunda/app/*");
    return filterRegistration;
  }
}
