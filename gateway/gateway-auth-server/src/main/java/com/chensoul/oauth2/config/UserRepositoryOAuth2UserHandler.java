package com.chensoul.oauth2.config;

import com.chensoul.oauth2.entity.Role;
import com.chensoul.oauth2.entity.User;
import com.chensoul.oauth2.repository.RoleRepository;
import com.chensoul.oauth2.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.function.Consumer;

@Component
@RequiredArgsConstructor
public final class UserRepositoryOAuth2UserHandler implements Consumer<OAuth2User> {

    private final UserRepository userRepository;

    private final RoleRepository roleRepository;

    @Override
    public void accept(OAuth2User oAuth2User) {
        DefaultOAuth2User defaultOAuth2User = (DefaultOAuth2User) oAuth2User;
        if (this.userRepository.findUserByUsername(oAuth2User.getName()) == null) {
            User user = new User();
            user.setUsername(defaultOAuth2User.getName());
            Role role = roleRepository.findByRoleCode(defaultOAuth2User.getAuthorities()
                    .stream().map(GrantedAuthority::getAuthority).findFirst().orElse("ROLE_OPERATION"));
            user.setRoleList(Arrays.asList(role));
            userRepository.save(user);
        }
    }
}
