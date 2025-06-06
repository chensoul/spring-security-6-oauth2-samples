package com.chensoul.domain;

import jakarta.persistence.*;

@Entity
@Table(name = "`users`")
public class User {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Integer id;

	@Column(length = 200)
	private String username;

	@Column(length = 500)
	private String password;

	public User() {
	}

	public User(String username, String password) {
		this.username = username;
		this.password = password;
	}

	public Integer getId() {
		return id;
	}

	public void setId(Integer id) {
		this.id = id;
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

}