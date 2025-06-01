package com.chensoul.keys;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Date;
import java.util.List;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

@Component
public class JdbcRsaKeyPairRepository implements RsaKeyPairRepository {

    private final JdbcTemplate jdbcTemplate;
    private final RsaPublicKeyConverter rsaPublicKeyConverter;
    private final RsaPrivateKeyConverter rsaPrivateKeyConverter;
    private final RowMapper<RsaKeyPair> keyPairRowMapper;

    public JdbcRsaKeyPairRepository(
            JdbcTemplate jdbcTemplate,
            RsaPublicKeyConverter rsaPublicKeyConverter,
            RsaPrivateKeyConverter rsaPrivateKeyConverter,
            RowMapper<RsaKeyPair> keyPairRowMapper) {
        this.jdbcTemplate = jdbcTemplate;
        this.rsaPublicKeyConverter = rsaPublicKeyConverter;
        this.rsaPrivateKeyConverter = rsaPrivateKeyConverter;
        this.keyPairRowMapper = keyPairRowMapper;
    }

    @Override
    public List<RsaKeyPair> findKeyPairs() {
        return jdbcTemplate.query("select * from rsa_key_pairs order by created desc", this.keyPairRowMapper);
    }

    @Override
    public void save(RsaKeyPair rsaKeyPair) {
        var sql = """
                insert into rsa_key_pairs (id, private_key, public_key, created) values (?, ?, ?, ?)
                """;
        try (var privateBaos = new ByteArrayOutputStream();
             var publicBaos = new ByteArrayOutputStream()) {
            this.rsaPrivateKeyConverter.serialize(rsaKeyPair.privateKey(), privateBaos);
            this.rsaPublicKeyConverter.serialize(rsaKeyPair.publicKey(), publicBaos);
            var updated = this.jdbcTemplate.update(sql,
                    rsaKeyPair.id(),
                    privateBaos.toString(),
                    publicBaos.toString(),
                    new Date(rsaKeyPair.created().toEpochMilli()));
            Assert.state(updated == 0 || updated == 1, "no more than one record should have been updated");
        } catch (IOException e) {
            throw new IllegalArgumentException("there's been an exception", e);
        }
    }
}