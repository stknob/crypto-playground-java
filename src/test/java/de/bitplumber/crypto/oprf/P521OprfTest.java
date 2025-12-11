/**
 * RFC 9497 OPRF implementation for Bouncy Castle EC
 *
 * Copyright (c) 2025 Stefan Knoblich <stkn@bitplumber.de>
 *
 * SPDX-License-Identifier: MIT
 */
package de.bitplumber.crypto.oprf;

import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

class P521OprfTest extends GenericOprfTestBase{
	private static final RFC9497OprfTestVector[] OPRF_TEST_VECTORS = new RFC9497OprfTestVector[]{
		// RFC 9497 - P512-SHA512 - OPRF - Test Vector 1, Batch Size 1
		new RFC9497OprfTestVector(
			Hex.decode("a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3"),
			Hex.decode("74657374206b6579"),
			Hex.decode("0153441b8faedb0340439036d6aed06d1217b34c42f17f8db4c5cc610a4a955d698a688831b16d0dc7713a1aa3611ec60703bffc7dc9c84e3ed673b3dbe1d5fccea6"),
			Hex.decode("00"),
			Hex.decode("00d1dccf7a51bafaf75d4a866d53d8cafe4d504650f53df8f16f6861633388936ea23338fa65ec36e0290022b48eb562889d89dbfa691d1cde91517fa222ed7ad364"),
			Hex.decode("0300e78bf846b0e1e1a3c320e353d758583cd876df56100a3a1e62bacba470fa6e0991be1be80b721c50c5fd0c672ba764457acc18c6200704e9294fbf28859d916351"),
			Hex.decode("030166371cf827cb2fb9b581f97907121a16e2dc5d8b10ce9f0ede7f7d76a0d047657735e8ad07bcda824907b3e5479bd72cdef6b839b967ba5c58b118b84d26f2ba07"),
			Hex.decode("26232de6fff83f812adadadb6cc05d7bbeee5dca043dbb16b03488abb9981d0a1ef4351fad52dbd7e759649af393348f7b9717566c19a6b8856284d69375c809")
		),
		// RFC 9497 - P512-SHA512 - OPRF - Test Vector 2, Batch Size 1
		new RFC9497OprfTestVector(
			Hex.decode("a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3"),
			Hex.decode("74657374206b6579"),
			Hex.decode("0153441b8faedb0340439036d6aed06d1217b34c42f17f8db4c5cc610a4a955d698a688831b16d0dc7713a1aa3611ec60703bffc7dc9c84e3ed673b3dbe1d5fccea6"),
			Hex.decode("5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"),
			Hex.decode("00d1dccf7a51bafaf75d4a866d53d8cafe4d504650f53df8f16f6861633388936ea23338fa65ec36e0290022b48eb562889d89dbfa691d1cde91517fa222ed7ad364"),
			Hex.decode("0300c28e57e74361d87e0c1874e5f7cc1cc796d61f9cad50427cf54655cdb455613368d42b27f94bf66f59f53c816db3e95e68e1b113443d66a99b3693bab88afb556b"),
			Hex.decode("0301ad453607e12d0cc11a3359332a40c3a254eaa1afc64296528d55bed07ba322e72e22cf3bcb50570fd913cb54f7f09c17aff8787af75f6a7faf5640cbb2d9620a6e"),
			Hex.decode("ad1f76ef939042175e007738906ac0336bbd1d51e287ebaa66901abdd324ea3ffa40bfc5a68e7939c2845e0fd37a5a6e76dadb9907c6cc8579629757fd4d04ba")
		),
	};

	@Test
	void testOprfTestVectors() { //NOSONAR
		final var oprf = ECCurveOprf.createP521();
		runTestVectors(oprf, OPRF_TEST_VECTORS);
	}
}
