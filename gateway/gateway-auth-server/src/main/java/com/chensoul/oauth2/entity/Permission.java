package com.chensoul.oauth2.entity;

import jakarta.persistence.*;
import lombok.Data;

@Data
@Entity
@Table(name = "`permission`")
public class Permission {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String permissionName;
    private String permissionCode;
}
