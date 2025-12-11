/**
 * RFC 9497 OPRF implementation for Bouncy Castle EC
 *
 * Copyright (c) 2025 Stefan Knoblich <stkn@bitplumber.de>
 *
 * SPDX-License-Identifier: MIT
 */
package de.bitplumber.crypto.oprf.bc;

import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

class P256OPRFTest extends GenericOPRFTestBase {
	/**
	 * OPRF Tests
	 **/
	private static final RFC9497OPRFTestVector[] OPRF_TEST_VECTORS = new RFC9497OPRFTestVector[]{
		// RFC 9497 - P256-SHA256 - OPRF - Test Vector 1, Batch Size 1
		new RFC9497OPRFTestVector(
			Hex.decode("a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3"),
			Hex.decode("74657374206b6579"),
			Hex.decode("159749d750713afe245d2d39ccfaae8381c53ce92d098a9375ee70739c7ac0bf"),
			Hex.decode("00"),
			Hex.decode("3338fa65ec36e0290022b48eb562889d89dbfa691d1cde91517fa222ed7ad364"),
			Hex.decode("03723a1e5c09b8b9c18d1dcbca29e8007e95f14f4732d9346d490ffc195110368d"),
			Hex.decode("030de02ffec47a1fd53efcdd1c6faf5bdc270912b8749e783c7ca75bb412958832"),
			Hex.decode("a0b34de5fa4c5b6da07e72af73cc507cceeb48981b97b7285fc375345fe495dd")
		),
		// RFC 9497 - P256-SHA256 - OPRF - Test Vector 2, Batch Size 1
		new RFC9497OPRFTestVector(
			Hex.decode("a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3"),
			Hex.decode("74657374206b6579"),
			Hex.decode("159749d750713afe245d2d39ccfaae8381c53ce92d098a9375ee70739c7ac0bf"),
			Hex.decode("5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"),
			Hex.decode("3338fa65ec36e0290022b48eb562889d89dbfa691d1cde91517fa222ed7ad364"),
			Hex.decode("03cc1df781f1c2240a64d1c297b3f3d16262ef5d4cf102734882675c26231b0838"),
			Hex.decode("03a0395fe3828f2476ffcd1f4fe540e5a8489322d398be3c4e5a869db7fcb7c52c"),
			Hex.decode("c748ca6dd327f0ce85f4ae3a8cd6d4d5390bbb804c9e12dcf94f853fece3dcce")
		),
	};

	@Test
	void testOPRFTestVectors() { //NOSONAR
		final var oprf = BcOPRF.createP256();
		runTestVectors(oprf, OPRF_TEST_VECTORS);
	}

	@Test
	void testOPRFRandomized() { //NOSONAR
		final var oprf = BcOPRF.createP256();
		runRandomizedRountrip(oprf);
	}

	/**
	 * VOPRF Tests
	 **/
	private static final RFC9497VOPRFTestVector[] VOPRF_TEST_VECTORS = new RFC9497VOPRFTestVector[]{
		//
		new RFC9497VOPRFTestVector(
			Hex.decode("a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3"),
			Hex.decode("74657374206b6579"),
			Hex.decode("ca5d94c8807817669a51b196c34c1b7f8442fde4334a7121ae4736364312fca6"),
			Hex.decode("03e17e70604bcabe198882c0a1f27a92441e774224ed9c702e51dd17038b102462"),
			Hex.decode("00"),
			Hex.decode("3338fa65ec36e0290022b48eb562889d89dbfa691d1cde91517fa222ed7ad364"),
			Hex.decode("02dd05901038bb31a6fae01828fd8d0e49e35a486b5c5d4b4994013648c01277da"),
			Hex.decode("0209f33cab60cf8fe69239b0afbcfcd261af4c1c5632624f2e9ba29b90ae83e4a2"),
			Hex.decode("e7c2b3c5c954c035949f1f74e6bce2ed539a3be267d1481e9ddb178533df4c2664f69d065c604a4fd953e100b856ad83804eb3845189babfa5a702090d6fc5fa"),
			Hex.decode("f9db001266677f62c095021db018cd8cbb55941d4073698ce45c405d1348b7b1"),
			Hex.decode("0412e8f78b02c415ab3a288e228978376f99927767ff37c5718d420010a645a1")
		),
		//
		new RFC9497VOPRFTestVector(
			Hex.decode("a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3"),
			Hex.decode("74657374206b6579"),
			Hex.decode("ca5d94c8807817669a51b196c34c1b7f8442fde4334a7121ae4736364312fca6"),
			Hex.decode("03e17e70604bcabe198882c0a1f27a92441e774224ed9c702e51dd17038b102462"),
			Hex.decode("5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"),
			Hex.decode("3338fa65ec36e0290022b48eb562889d89dbfa691d1cde91517fa222ed7ad364"),
			Hex.decode("03cd0f033e791c4d79dfa9c6ed750f2ac009ec46cd4195ca6fd3800d1e9b887dbd"),
			Hex.decode("030d2985865c693bf7af47ba4d3a3813176576383d19aff003ef7b0784a0d83cf1"),
			Hex.decode("2787d729c57e3d9512d3aa9e8708ad226bc48e0f1750b0767aaff73482c44b8d2873d74ec88aebd3504961acea16790a05c542d9fbff4fe269a77510db00abab"),
			Hex.decode("f9db001266677f62c095021db018cd8cbb55941d4073698ce45c405d1348b7b1"),
			Hex.decode("771e10dcd6bcd3664e23b8f2a710cfaaa8357747c4a8cbba03133967b5c24f18")
		),
	};

	@Test
	void testVOPRFTestVectors() { //NOSONAR
		final var voprf = BcVOPRF.createP256();
		runTestVectors(voprf, VOPRF_TEST_VECTORS);
	}

	@Test
	void testVOPRFRandomized() { //NOSONAR
		final var voprf = BcVOPRF.createP256();
		runRandomizedRountrip(voprf);
	}

	/**
	 * POPRF Tests
	 **/
	private static final RFC9497POPRFTestVector[] POPRF_TEST_VECTORS = new RFC9497POPRFTestVector[]{
		// ristretto255-SHA512 - POPRF - Test Vector 1, Batch Size 1
		new RFC9497POPRFTestVector(
			Hex.decode("a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3"),
			Hex.decode("74657374206b6579"),
			Hex.decode("6ad2173efa689ef2c27772566ad7ff6e2d59b3b196f00219451fb2c89ee4dae2"),
			Hex.decode("030d7ff077fddeec965db14b794f0cc1ba9019b04a2f4fcc1fa525dedf72e2a3e3"),
			Hex.decode("7465737420696e666f"),
			Hex.decode("00"),
			Hex.decode("3338fa65ec36e0290022b48eb562889d89dbfa691d1cde91517fa222ed7ad364"),
			Hex.decode("031563e127099a8f61ed51eeede05d747a8da2be329b40ba1f0db0b2bd9dd4e2c0"),
			Hex.decode("02c5e5300c2d9e6ba7f3f4ad60500ad93a0157e6288eb04b67e125db024a2c74d2"),
			Hex.decode("f8a33690b87736c854eadfcaab58a59b8d9c03b569110b6f31f8bf7577f3fbb85a8a0c38468ccde1ba942be501654adb106167c8eb178703ccb42bccffb9231a"),
			Hex.decode("f9db001266677f62c095021db018cd8cbb55941d4073698ce45c405d1348b7b1"),
			Hex.decode("193a92520bd8fd1f37accb918040a57108daa110dc4f659abe212636d245c592")
		),
		// ristretto255-SHA512 - POPRF - Test Vector 2, Batch Size 1
		new RFC9497POPRFTestVector(
			Hex.decode("a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3"),
			Hex.decode("74657374206b6579"),
			Hex.decode("6ad2173efa689ef2c27772566ad7ff6e2d59b3b196f00219451fb2c89ee4dae2"),
			Hex.decode("030d7ff077fddeec965db14b794f0cc1ba9019b04a2f4fcc1fa525dedf72e2a3e3"),
			Hex.decode("7465737420696e666f"),
			Hex.decode("5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"),
			Hex.decode("3338fa65ec36e0290022b48eb562889d89dbfa691d1cde91517fa222ed7ad364"),
			Hex.decode("021a440ace8ca667f261c10ac7686adc66a12be31e3520fca317643a1eee9dcd4d"),
			Hex.decode("0208ca109cbae44f4774fc0bdd2783efdcb868cb4523d52196f700210e777c5de3"),
			Hex.decode("043a8fb7fc7fd31e35770cabda4753c5bf0ecc1e88c68d7d35a62bf2631e875af4613641be2d1875c31d1319d191c4bbc0d04875f4fd03c31d3d17dd8e069b69"),
			Hex.decode("f9db001266677f62c095021db018cd8cbb55941d4073698ce45c405d1348b7b1"),
			Hex.decode("1e6d164cfd835d88a31401623549bf6b9b306628ef03a7962921d62bc5ffce8c")
		),
	};

	@Test
	void testPOPRFTestVectors() { //NOSONAR
		final var poprf = BcPOPRF.createP256();
		runTestVectors(poprf, POPRF_TEST_VECTORS);
	}

	@Test
	void testPOPRFRandomized() { //NOSONAR
		final var poprf = BcPOPRF.createP256();
		runRandomizedRountrip(poprf);
	}
}
