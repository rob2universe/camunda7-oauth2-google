package org.camunda.example.sso.rest;

import lombok.extern.slf4j.Slf4j;
import org.camunda.bpm.engine.IdentityService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

@Slf4j
@Component
public class CamundaSpringHttpAuthProvider implements AuthenticationProvider {

    @Autowired
    private IdentityService identityService;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        if (authentication instanceof UsernamePasswordAuthenticationToken) {
            if (authentication.getCredentials() != null) {
                String name = authentication.getPrincipal() + "";
                String password = authentication.getCredentials() + "";
                log.debug("Authentication UsernamePasswordAuthenticationToken for: {}", name);

                boolean match = identityService.checkPassword(name, password);
                log.debug("Password check " + (match ? "succeeded." : "failed."));
                if (!match) throw new AuthenticationException("Password did not match") {
                };

                //get groups from Camunda user management and add them to Spring authorizations
                var existingAuthorities = (Collection<SimpleGrantedAuthority>) authentication.getAuthorities();
                var updatedAuthorities = new ArrayList<SimpleGrantedAuthority>();
                if (existingAuthorities != null) updatedAuthorities.addAll(existingAuthorities);

                // add default role
                updatedAuthorities.add(new SimpleGrantedAuthority("ROLE_USER"));
                var groups = identityService.createGroupQuery().groupMember(name).list();
                if (groups != null) {
                    for (var group : groups) {
                        log.debug("Adding Camunda authorization: {}", group.getName());
                        updatedAuthorities.add(new SimpleGrantedAuthority("ROLE_" + group.getId()));
                    }
                }

                //update authentication
                SecurityContextHolder.getContext().setAuthentication(
                        new UsernamePasswordAuthenticationToken(
                                authentication.getPrincipal(),
                                authentication.getCredentials(),
                                updatedAuthorities)
                );

                //propagate user and combined authorizations to Camunda
                identityService.setAuthentication(name, getUserGroups(name));
            }
            return authentication;
        } else
            throw new AuthenticationException("Authentication is not an instance of UsernamePasswordAuthenticationToken.") {
            };
    }

    private List<String> getUserGroups(String userId) {
        List<String> groupIds;
        org.springframework.security.core.Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        groupIds = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .map(res -> res.substring(5)) // Strip "ROLE_"
                .collect(Collectors.toList());
        log.info("groupIds from authentication: {}", groupIds);
        return groupIds;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.isAssignableFrom(UsernamePasswordAuthenticationToken.class);
    }
}
