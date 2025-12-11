/**
 * RFC 9497 OPRF implementation for Bouncy Castle EC
 *
 * Copyright (c) 2025 Stefan Knoblich <stkn@bitplumber.de>
 *
 * SPDX-License-Identifier: MIT
 */
package de.bitplumber.crypto.oprf.bc;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

class Secp256k1OprfTest extends GenericOprfTestBase {
	private static final RFC9497OprfTestVector[] OPRF_TEST_VECTORS = new RFC9497OprfTestVector[]{ /* No testvectors available */};
	private static final RFC9497PoprfTestVector[] POPRF_TEST_VECTORS = new RFC9497PoprfTestVector[]{ /* No testvectors available */};
	private static final RFC9497VoprfTestVector[] VOPRF_TEST_VECTORS = new RFC9497VoprfTestVector[]{ /* No testvectors available */};

	@Test @Disabled("No test vectors available")
	void testOprfTestVectors() { //NOSONAR
		final var oprf = ECCurveOprf.createSecp256k1();
		runTestVectors(oprf, OPRF_TEST_VECTORS);
	}

	@Test @Disabled("No test vectors available")
	void testPoprfTestVectors() { //NOSONAR
		final var poprf = ECCurvePoprf.createSecp256k1();
		runTestVectors(poprf, POPRF_TEST_VECTORS);
	}

	@Test @Disabled("No test vectors available")
	void testVoprfTestVectors() { //NOSONAR
		final var voprf = ECCurveVoprf.createSecp256k1();
		runTestVectors(voprf, VOPRF_TEST_VECTORS);
	}

	@Test
	void testOprfRandomized() { //NOSONAR
		final var oprf = ECCurveOprf.createSecp256k1();
		runRandomizedRountrip(oprf);
	}

	@Test
	void testPoprfRandomized() { //NOSONAR
		final var poprf = ECCurvePoprf.createSecp256k1();
		runRandomizedRountrip(poprf);
	}

	@Test
	void testVoprfRandomized() { //NOSONAR
		final var voprf = ECCurveVoprf.createSecp256k1();
		runRandomizedRountrip(voprf);
	}
}
