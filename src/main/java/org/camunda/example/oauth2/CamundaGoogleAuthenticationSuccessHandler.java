package org.camunda.example.oauth2;

import lombok.extern.slf4j.Slf4j;
import org.camunda.bpm.engine.IdentityService;
import org.camunda.bpm.engine.ManagementService;
import org.camunda.bpm.engine.identity.Group;
import org.camunda.bpm.engine.identity.User;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Service;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;

// Maps Google user attributes to Camunda user attributes and creates the user in Camunda if it does not exist
@Slf4j
@Service
public class CamundaGoogleAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private IdentityService identityService;

    @Value("camunda.bpm.admin-user.id")
    private String adminId;

    public CamundaGoogleAuthenticationSuccessHandler(IdentityService identityService) {
        this.identityService = identityService;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {

        OAuth2User oauth2User = (OAuth2User) authentication.getPrincipal();
        User user = identityService.createUserQuery().userId(oauth2User.getName()).singleResult();
        if (user == null)
        {
            log.debug("Creating user for principal: {}", oauth2User.getName());
            user = identityService.newUser(oauth2User.getName());
            user.setFirstName(oauth2User.getAttribute("given_name"));
            user.setLastName(oauth2User.getAttribute("family_name"));
            user.setEmail(oauth2User.getAttribute("email"));
            identityService.saveUser(user);
        }

        if (user.getId().equals(adminId)) {
            identityService.createMembership(oauth2User.getName(), "camunda-admin");
            var newAuthorities = new ArrayList<SimpleGrantedAuthority>();
            newAuthorities.add(new SimpleGrantedAuthority("ROLE_camunda-admin"));
            newAuthorities.addAll((Collection<SimpleGrantedAuthority>) SecurityContextHolder.getContext().getAuthentication().getAuthorities());

            SecurityContextHolder.getContext().setAuthentication(
                    new UsernamePasswordAuthenticationToken(
                            SecurityContextHolder.getContext().getAuthentication().getPrincipal(),
                            SecurityContextHolder.getContext().getAuthentication().getCredentials(),
                            newAuthorities)
            );
        };

        response.sendRedirect("/camunda/app/");
    }
}
