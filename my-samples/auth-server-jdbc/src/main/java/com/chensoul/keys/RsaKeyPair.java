package com.chensoul.keys;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Objects;

public final class RsaKeyPair {

	private final String id;

	private final Instant created;

	private final RSAPublicKey publicKey;

	private final RSAPrivateKey privateKey;

	public RsaKeyPair(String id, Instant created, RSAPublicKey publicKey, RSAPrivateKey privateKey) {
		this.id = id;
		this.created = created;
		this.publicKey = publicKey;
		this.privateKey = privateKey;
	}

	public String id() {
		return id;
	}

	public Instant created() {
		return created;
	}

	public RSAPublicKey publicKey() {
		return publicKey;
	}

	public RSAPrivateKey privateKey() {
		return privateKey;
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == this)
			return true;
		if (obj == null || obj.getClass() != this.getClass())
			return false;
		var that = (RsaKeyPair) obj;
		return Objects.equals(this.id, that.id) && Objects.equals(this.created, that.created)
				&& Objects.equals(this.publicKey, that.publicKey) && Objects.equals(this.privateKey, that.privateKey);
	}

	@Override
	public int hashCode() {
		return Objects.hash(id, created, publicKey, privateKey);
	}

	@Override
	public String toString() {
		return "RsaKeyPair[" + "id=" + id + ", " + "created=" + created + ", " + "publicKey=" + publicKey + ", "
				+ "privateKey=" + privateKey + ']';
	}

}