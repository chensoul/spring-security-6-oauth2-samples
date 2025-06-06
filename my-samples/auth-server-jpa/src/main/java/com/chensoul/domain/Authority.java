package com.chensoul.domain;

import jakarta.persistence.*;

/**
 * TODO Comment
 *
 * @author <a href="mailto:ichensoul@gmail.com">chensoul</a>
 * @since TODO
 */
@Entity
@Table(name = "`authority`")
public class Authority {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Integer id;

	@Column(length = 200)
	private String username;

	@Column(length = 50)
	private String authority;

	public Authority() {
	}

	public Authority(String username, String authority) {
		this.username = username;
		this.authority = authority;
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

	public String getAuthority() {
		return authority;
	}

	public void setAuthority(String authority) {
		this.authority = authority;
	}

}
