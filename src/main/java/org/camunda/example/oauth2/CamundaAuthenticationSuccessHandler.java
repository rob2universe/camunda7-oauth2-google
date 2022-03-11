package org.camunda.example.oauth2;

import lombok.extern.slf4j.Slf4j;
import org.camunda.bpm.engine.IdentityService;
import org.camunda.bpm.engine.identity.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;


@Slf4j
public class CamundaAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    @Autowired
    private IdentityService identityService;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {

        GoogleOAuth2User oauthUser = (GoogleOAuth2User) authentication.getPrincipal();
        log.debug("Creating user for principal: {}", oauthUser.getName());

        final User user = identityService.newUser(oauthUser.getName());
        user.setFirstName(oauthUser.getGivenName());
        user.setLastName(oauthUser.getFamilyName());
        user.setEmail(oauthUser.getEmail());
        identityService.saveUser(user);
//            response.sendRedirect("/camunda/app/tasklist");
    }
}
