package com.chensoul.keys;

import java.util.List;

public interface RsaKeyPairRepository {

	List<RsaKeyPair> findKeyPairs();

	void save(RsaKeyPair rsaKeyPair);

}