package com.chensoul.oauth2.entity;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Data;


@Data
@Entity
@Table(name = "`role`")
public class Role {
    @Id
    private Long id;
    private String roleCode;
}
