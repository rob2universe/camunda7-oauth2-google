package org.camunda.example.filter.rest;

import lombok.extern.slf4j.Slf4j;
import org.camunda.bpm.engine.IdentityService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.util.ArrayList;

@Slf4j
@Component
public class CamundaUserDetailsService implements UserDetailsService {

    @Autowired
    private IdentityService identityService;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        log.info("CamundaUserDetailsService getting user details for {} from IdentityService", username);
        var camundaUser = identityService.createUserQuery().userId(username).singleResult();
        log.info("User found: {}", camundaUser);

        var authorities = new ArrayList<SimpleGrantedAuthority>();
        authorities.add(new SimpleGrantedAuthority("ROLE_USER"));

        return new User(username, camundaUser.getPassword(), true, true, true,
                true, authorities);
    }
}