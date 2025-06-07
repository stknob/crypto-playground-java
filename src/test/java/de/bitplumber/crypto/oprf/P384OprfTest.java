package de.bitplumber.crypto.oprf;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

class P384OprfTest {
	private static final record RFC9497TestVector(byte[] seed, byte[] keyInfo, byte[] secretKey, byte[] input,
		byte[] blind, byte[] blindedElement, byte[] evaluationElement, byte[] output) {}

	private static final RFC9497TestVector[] RFC9497TestVectors = new RFC9497TestVector[]{
		// RFC 9497 - P384-SHA384 - OPRF - Test Vector 1, Batch Size 1
		new RFC9497TestVector(
			Hex.decode("a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3"),
			Hex.decode("74657374206b6579"),
			Hex.decode("dfe7ddc41a4646901184f2b432616c8ba6d452f9bcd0c4f75a5150ef2b2ed02ef40b8b92f60ae591bcabd72a6518f188"),
			Hex.decode("00"),
			Hex.decode("504650f53df8f16f6861633388936ea23338fa65ec36e0290022b48eb562889d89dbfa691d1cde91517fa222ed7ad364"),
			Hex.decode("02a36bc90e6db34096346eaf8b7bc40ee1113582155ad3797003ce614c835a874343701d3f2debbd80d97cbe45de6e5f1f"),
			Hex.decode("03af2a4fc94770d7a7bf3187ca9cc4faf3732049eded2442ee50fbddda58b70ae2999366f72498cdbc43e6f2fc184afe30"),
			Hex.decode("ed84ad3f31a552f0456e58935fcc0a3039db42e7f356dcb32aa6d487b6b815a07d5813641fb1398c03ddab5763874357")
		),
		// RFC 9497 - P384-SHA384 - OPRF - Test Vector 2, Batch Size 1
		new RFC9497TestVector(
			Hex.decode("a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3"),
			Hex.decode("74657374206b6579"),
			Hex.decode("dfe7ddc41a4646901184f2b432616c8ba6d452f9bcd0c4f75a5150ef2b2ed02ef40b8b92f60ae591bcabd72a6518f188"),
			Hex.decode("5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"),
			Hex.decode("504650f53df8f16f6861633388936ea23338fa65ec36e0290022b48eb562889d89dbfa691d1cde91517fa222ed7ad364"),
			Hex.decode("02def6f418e3484f67a124a2ce1bfb19de7a4af568ede6a1ebb2733882510ddd43d05f2b1ab5187936a55e50a847a8b900"),
			Hex.decode("034e9b9a2960b536f2ef47d8608b21597ba400d5abfa1825fd21c36b75f927f396bf3716c96129d1fa4a77fa1d479c8d7b"),
			Hex.decode("dd4f29da869ab9355d60617b60da0991e22aaab243a3460601e48b075859d1c526d36597326f1b985778f781a1682e75")
		),
	};

	@Test
	void testRFC9497TestVectors() {
		final var oprf = ECCurveOprf.createP384();

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
}
