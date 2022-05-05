package org.camunda.example.sso.webapp.oauth2;

import lombok.extern.slf4j.Slf4j;
import org.camunda.bpm.engine.IdentityService;
import org.camunda.bpm.engine.identity.User;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;

/* Maps Google user attributes to Camunda user attributes
   and creates the user in Camunda if it does not exist */
@Slf4j
@Service
public class CamundaGoogleAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private final IdentityService identityService;

    @Value("${camunda.sso.admin-user-id}")
    private String adminId;

    public CamundaGoogleAuthenticationSuccessHandler(IdentityService identityService) {
        this.identityService = identityService;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {

        OAuth2User oauth2User = (OAuth2User) authentication.getPrincipal();
        // if user does not exist in Camunda user management create it
        User user = identityService.createUserQuery().userId(oauth2User.getName()).singleResult();
        if (user == null) {
            log.debug("Creating user for Google principal: {}", oauth2User.getName());
            user = identityService.newUser(oauth2User.getName());
            user.setFirstName(oauth2User.getAttribute("given_name"));
            user.setLastName(oauth2User.getAttribute("family_name"));
            user.setEmail(oauth2User.getAttribute("email"));
            identityService.saveUser(user);
        }

        // if admin user id in properties matches oauth user id then grant admin authority
        log.debug("Comparing admin userId {} to userId {}", adminId, user.getId());
        if (user.getId().equals(adminId)) {
            //add admin role to security context
            var newAuthorities = new ArrayList<SimpleGrantedAuthority>();
            newAuthorities.add(new SimpleGrantedAuthority("ROLE_camunda-admin"));
            newAuthorities.addAll((Collection<SimpleGrantedAuthority>) authentication.getAuthorities());
            SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(authentication.getPrincipal(), authentication.getCredentials(), newAuthorities));

            // if not already exists grant admin group membership in Camunda
            if (identityService.createUserQuery().memberOfGroup("camunda-admin").userId(user.getId()).singleResult() == null) {
                identityService.createMembership(oauth2User.getName(), "camunda-admin");
            }
        }
        response.sendRedirect("/camunda/app/");
    }
}