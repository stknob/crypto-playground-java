package de.bitplumber.crypto.oprf;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

class P256OprfTest {
	private static final record RFC9497TestVector(byte[] seed, byte[] keyInfo, byte[] secretKey, byte[] input,
		byte[] blind, byte[] blindedElement, byte[] evaluationElement, byte[] output) {}

	private static final RFC9497TestVector[] RFC9497TestVectors = new RFC9497TestVector[]{
		// RFC 9497 - P256-SHA256 - OPRF - Test Vector 1, Batch Size 1
		new RFC9497TestVector(
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
		new RFC9497TestVector(
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
}
