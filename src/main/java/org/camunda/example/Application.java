package org.camunda.example;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.RequestMapping;

import java.security.Principal;

@Slf4j
@SpringBootApplication
public class Application {

  public static void main(String... args) {
    SpringApplication.run(Application.class, args);
  }

  @RequestMapping(value = "/user")
  public Principal user(Principal principal) {

    log.debug("HERE:" + principal);
    return principal;
  }

}