package de.bitplumber.crypto.oprf;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import java.nio.charset.StandardCharsets;
import java.util.Objects;

import org.bouncycastle.crypto.Xof;
import org.bouncycastle.crypto.digests.CSHAKEDigest;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

class Secp256k1OprfTest {
	private static final record RFC9497TestVector(byte[] seed, byte[] keyInfo, byte[] secretKey, byte[] input,
		byte[] blind, byte[] blindedElement, byte[] evaluationElement, byte[] output) {}

	private static final RFC9497TestVector[] RFC9497TestVectors = new RFC9497TestVector[]{
		// No RFC testvectors available for this suite
	};

	@Test @Disabled
	void testRFC9497TestVectors() {
		final var oprf = ECCurveOprf.createP256();

		for (final var vector : RFC9497TestVectors) {
			final var keypair = assertDoesNotThrow(() -> oprf.deriveKeyPair(vector.seed(), vector.keyInfo()));
			assertArrayEquals(vector.secretKey(), keypair.secretKey(), "secretKey");

			final var blindResult = assertDoesNotThrow(() -> oprf.blind(vector.input(), vector.blind()));
			assertArrayEquals(vector.blindedElement(), oprf.encodeElement(blindResult.blindedElement()), "blindedElement");
			assertArrayEquals(vector.blind(), oprf.encodeScalar(blindResult.blind()), "blind");

			final var blindEvaluateResult = assertDoesNotThrow(() -> oprf.blindEvaluate(keypair.secretKey(), blindResult.blindedElement()));
			assertArrayEquals(vector.evaluationElement(), oprf.encodeElement(blindEvaluateResult), "evaluationElement");

			final var finalizeResult = assertDoesNotThrow(() -> oprf.finalize(vector.input(), blindResult.blind(), blindEvaluateResult));
			assertArrayEquals(vector.output(), finalizeResult, "finalize output");

			final var evaluateResult = assertDoesNotThrow(() -> oprf.evaluate(keypair.secretKey(), vector.input()));
			assertArrayEquals(vector.output(), evaluateResult, "evaluate output");
		}
	}

	private Xof hashXOF(byte[] seed, byte[] dst) {
		final var h = new CSHAKEDigest(256, null, Objects.requireNonNullElse(dst, "".getBytes(StandardCharsets.UTF_8)));
		h.update(seed, 0, seed.length);
		return h;
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
