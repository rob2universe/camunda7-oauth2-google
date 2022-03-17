package org.camunda.example.filter.rest;

import lombok.extern.slf4j.Slf4j;
import org.camunda.bpm.engine.IdentityService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class CamundaPasswordEncoder implements PasswordEncoder {

    @Autowired
    private IdentityService identityService;

    @Override
    public String encode(CharSequence plainTextPassword) {
        log.warn("encryption not implemented. Create users via IdentityService.");
        return plainTextPassword.toString();
    }

    @Override
    public boolean matches(CharSequence plainTextPassword, String passwordInDatabase) {
        return identityService.checkPassword("rest", plainTextPassword.toString());
    }
}
