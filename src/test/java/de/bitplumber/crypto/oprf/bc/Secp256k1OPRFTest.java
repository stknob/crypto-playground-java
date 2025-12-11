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

class Secp256k1OPRFTest extends GenericOPRFTestBase {
	private static final RFC9497OPRFTestVector[] OPRF_TEST_VECTORS = new RFC9497OPRFTestVector[]{ /* No testvectors available */};
	private static final RFC9497POPRFTestVector[] POPRF_TEST_VECTORS = new RFC9497POPRFTestVector[]{ /* No testvectors available */};
	private static final RFC9497VOPRFTestVector[] VOPRF_TEST_VECTORS = new RFC9497VOPRFTestVector[]{ /* No testvectors available */};

	@Test @Disabled("No test vectors available")
	void testOPRFTestVectors() { //NOSONAR
		final var oprf = BcOPRF.createSecp256k1();
		runTestVectors(oprf, OPRF_TEST_VECTORS);
	}

	@Test @Disabled("No test vectors available")
	void testPOPRFTestVectors() { //NOSONAR
		final var poprf = BcPOPRF.createSecp256k1();
		runTestVectors(poprf, POPRF_TEST_VECTORS);
	}

	@Test @Disabled("No test vectors available")
	void testVOPRFTestVectors() { //NOSONAR
		final var voprf = BcVOPRF.createSecp256k1();
		runTestVectors(voprf, VOPRF_TEST_VECTORS);
	}

	@Test
	void testOPRFRandomized() { //NOSONAR
		final var oprf = BcOPRF.createSecp256k1();
		runRandomizedRountrip(oprf);
	}

	@Test
	void testPOPRFRandomized() { //NOSONAR
		final var poprf = BcPOPRF.createSecp256k1();
		runRandomizedRountrip(poprf);
	}

	@Test
	void testVOPRFRandomized() { //NOSONAR
		final var voprf = BcVOPRF.createSecp256k1();
		runRandomizedRountrip(voprf);
	}
}
