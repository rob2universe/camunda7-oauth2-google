package org.camunda.example.filter.rest;


import lombok.extern.slf4j.Slf4j;
import org.camunda.bpm.engine.ProcessEngine;
import org.camunda.bpm.engine.rest.util.EngineUtil;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;

import javax.servlet.*;
import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

@Slf4j
public class StatelessUserAuthenticationFilter implements Filter {

    @Override
    public void init(FilterConfig filterConfig) {

    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        log.info("Applying StatelessUserAuthenticationFilter");
        // Current limitation: Only works for the default engine
        ProcessEngine engine = EngineUtil.lookupProcessEngine("default");

        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        String name;

        if (principal instanceof UserDetails) {
            name = ((UserDetails) principal).getUsername();
            log.debug("Authentication UserDetails: {}", principal);
        } else {
            name = principal.toString();
        }

        try {
            log.info("Setting authentication for {}", name);
            engine.getIdentityService().setAuthentication(name, getUserGroups(name));
            chain.doFilter(request, response);
        } finally {
            clearAuthentication(engine);
        }
    }

    @Override
    public void destroy() {
    }

    private void clearAuthentication(ProcessEngine engine) {
        engine.getIdentityService().clearAuthentication();
    }

    private List<String> getUserGroups(String userId) {
        List<String> groupIds;
        org.springframework.security.core.Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        groupIds = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .map(res -> res.substring(5)) // Strip "ROLE_"
                .collect(Collectors.toList());
        return groupIds;
    }
}
