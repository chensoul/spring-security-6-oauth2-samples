package com.chensoul.oauth2.config;

import com.chensoul.oauth2.entity.Role;
import com.chensoul.oauth2.repository.UserRepository;
import java.util.Set;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.util.CollectionUtils;
import org.springframework.util.ObjectUtils;

@RequiredArgsConstructor
public class JdbcUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        com.chensoul.oauth2.entity.User user = userRepository.findUserByUsername(username);
        if (ObjectUtils.isEmpty(user)) {
            throw new UsernameNotFoundException("user is not found");
        }
        if (CollectionUtils.isEmpty(user.getRoleList())) {
            throw new UsernameNotFoundException("role is not found");
        }
        Set<SimpleGrantedAuthority> authorities = user.getRoleList().stream().map(Role::getRoleCode)
                .map(SimpleGrantedAuthority::new).collect(Collectors.toSet());
        return new User(user.getUsername(), user.getPassword(), authorities);
    }
}
