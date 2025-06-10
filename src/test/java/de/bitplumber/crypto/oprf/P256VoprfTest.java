package de.bitplumber.crypto.oprf;

import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

class P256VoprfTest extends GenericOprfTestBase{
	private static final RFC9497VoprfTestVector[] VOPRF_TEST_VECTORS = new RFC9497VoprfTestVector[]{
		//
		new RFC9497VoprfTestVector(
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
		new RFC9497VoprfTestVector(
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
	void testVoprfTestVectors() { //NOSONAR
		final var voprf = ECCurveVoprf.createP256();
		runTestVectors(voprf, VOPRF_TEST_VECTORS);
	}
}
