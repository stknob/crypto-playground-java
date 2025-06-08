package de.bitplumber.crypto.oprf;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

class Secp256k1OprfTest extends GenericOprfTestBase {
	private static final RFC9497OprfTestVector[] RFC9497TestVectors = new RFC9497OprfTestVector[]{
		// No RFC testvectors available for this suite
	};

	@Test @Disabled("No test vectors available")
	void testRFC9497TestVectors() {
		final var oprf = ECCurveOprf.createP256();
		runOprfTestVectors(oprf, RFC9497TestVectors);
	}

	@Test
	void testRoundtrips() {
		final var seed = Hex.decode("a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3");
		final var keyInfo = Hex.decode("74657374206b6579");
		final var keySeed = new byte[32];
		final var input   = new byte[32];

		final var hash = hashXOF(seed, null);
		final var oprf = ECCurveOprf.createSecp256k1();
		for (int i = 0; i < 1000; i++) {
			hash.doOutput(keySeed, 0, keySeed.length);
			hash.doOutput(input,   0, input.length);

			final var keypair = assertDoesNotThrow(() -> oprf.deriveKeyPair(keySeed, keyInfo));
			final var blindResult = assertDoesNotThrow(() -> oprf.blind(input));
			final var blindEvaluateResult = assertDoesNotThrow(() -> oprf.blindEvaluate(keypair.secretKey(), blindResult.blindedElement()));
			final var finalizeResult = assertDoesNotThrow(() -> oprf.finalize(input, blindResult.blind(), blindEvaluateResult));
			final var evaluateResult = assertDoesNotThrow(() -> oprf.evaluate(keypair.secretKey(), input));
			assertArrayEquals(finalizeResult, evaluateResult, "evaluate and finalize outputs do not match");
		}
	}
}
