package de.bitplumber.crypto.oprf;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

class Secp256k1OprfTest extends GenericOprfTestBase {
	private static final RFC9497OprfTestVector[] OPRF_TEST_VECTORS = new RFC9497OprfTestVector[]{ /* No testvectors available */};
	private static final RFC9497PoprfTestVector[] POPRF_TEST_VECTORS = new RFC9497PoprfTestVector[]{ /* No testvectors available */};
	private static final RFC9497VoprfTestVector[] VOPRF_TEST_VECTORS = new RFC9497VoprfTestVector[]{ /* No testvectors available */};

	@Test @Disabled("No test vectors available")
	void testRFC9497OprfTestVectors() {
		final var oprf = ECCurveOprf.createP256();
		runTestVectors(oprf, OPRF_TEST_VECTORS);
	}

	@Test @Disabled("No test vectors available")
	void testRFC9497PoprfTestVectors() {
		final var poprf = ECCurvePoprf.createP256();
		runTestVectors(poprf, POPRF_TEST_VECTORS);
	}

	@Test @Disabled("No test vectors available")
	void testRFC9497VoprfTestVectors() {
		final var voprf = ECCurveVoprf.createP256();
		runTestVectors(voprf, VOPRF_TEST_VECTORS);
	}

	@Test
	void testOprfRoundtrips() {
		final var oprf = ECCurveOprf.createSecp256k1();
		runRandomizedRountrip(oprf);
	}

	@Test
	void testPoprfRoundtrips() {
		final var poprf = ECCurvePoprf.createSecp256k1();
		runRandomizedRountrip(poprf);
	}

	@Test
	void testVoprfRoundtrips() {
		final var voprf = ECCurveVoprf.createSecp256k1();
		runRandomizedRountrip(voprf);
	}
}
