package org.camunda.example.oauth2;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Collection;
import java.util.Map;

// Authentication: OAuth2AuthenticationToken [Principal=Name: [115479104114804903125],
// Granted Authorities: [[ROLE_USER, SCOPE_https://www.googleapis.com/auth/userinfo.email,
// SCOPE_https://www.googleapis.com/auth/userinfo.profile, SCOPE_openid]],
// Details=WebAuthenticationDetails [RemoteIpAddress=127.0.0.1, SessionId=4E374F4F93AC47A866869C09886CFFEA],
// Granted Authorities=[ROLE_USER, SCOPE_https://www.googleapis.com/auth/userinfo.email, SCOPE_https://www.googleapis.com/auth/userinfo.profile, SCOPE_openid]]
// User Attributes: [{at_hash=l1MZh8IhoFou3EzM0vsKEA, sub=115479104114804903125,
// email_verified=true,
// iss=https://accounts.google.com,
// given_name=Robert, locale=en, nonce=FirhuJSzCWgYfVVVfB92T491G9ff-0r0mnsJz65-yR8,
// picture=https://lh3.googleusercontent.com/a/AATXAJzEgzzR_Srv3rxvx0ZZhH0hUNR0RwSY8dpjgk7how=s96-c,
// aud=[832780395862-sk6knpak6t0uln900d8671tiib0vt008.apps.googleusercontent.com],
// azp=832780395862-sk6knpak6t0uln900d8671tiib0vt008.apps.googleusercontent.com,
// name=Robert Emsbach, exp=2022-03-11T06:25:47Z,
// family_name=Emsbach, iat=2022-03-11T05:25:47Z, email=robert.emsbach@gmail.com}], Credentials=[PROTECTED], Authenticated=true,

public class GoogleOAuth2User implements OAuth2User {

    private OAuth2User oauth2User;

    public GoogleOAuth2User(OAuth2User oauth2User) {
        this.oauth2User = oauth2User;
    }

    @Override
    public Map<String, Object> getAttributes() {
        return oauth2User.getAttributes();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return oauth2User.getAuthorities();
    }

    @Override
    public String getName() {
        return oauth2User.getAttribute("name");
    }

    public String getId() { return oauth2User.getName(); }

    public String getGivenName() {
        return oauth2User.getAttribute("given_name");
    }

    public String getFamilyName() {
        return oauth2User.getAttribute("family_name");
    }

    public String getEmail() {
        return oauth2User.<String>getAttribute("email");
    }


}
