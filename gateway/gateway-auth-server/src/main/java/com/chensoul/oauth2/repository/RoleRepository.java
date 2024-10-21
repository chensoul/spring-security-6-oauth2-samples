package com.chensoul.oauth2.repository;

import com.chensoul.oauth2.entity.Role;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepository extends JpaRepository<Role, Long> {

    Role findByRoleCode(String roleCode);
}
