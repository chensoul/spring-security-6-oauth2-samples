package com.chensoul.domain;

import lombok.Getter;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;

import java.nio.file.attribute.UserPrincipal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.UUID;

public class SecurityUser extends User {
    private Collection<GrantedAuthority> authorities;
    @Getter
    @Setter
    private boolean enabled;
    @Getter
    @Setter
    private UserPrincipal userPrincipal;
    @Getter
    @Setter
    private String sessionId = UUID.randomUUID().toString();

    public Collection<GrantedAuthority> getAuthorities() {
        if (authorities == null) {
            authorities = new ArrayList<>();
        }
        return authorities;
    }

}