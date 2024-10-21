package com.chensoul.oauth2.entity;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.JoinTable;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import lombok.Data;


@Data
@Entity
@Table(name = "`oauth2_client_role`")
public class OAuth2ClientRole {
    @Id
    private Long id;
    private String clientRegistrationId;
    private String roleCode;

    @ManyToOne
    @JoinTable(
            name = "oauth2_client_role_mapping",
            joinColumns = {
                    @JoinColumn(name = "oauth_client_role_id")
            },
            inverseJoinColumns = {
                    @JoinColumn(name = "role_id")
            }
    )
    private Role role;
}
