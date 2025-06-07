package de.bitplumber.crypto.oprf;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

class P384VoprfTest {
	private static final record RFC9497TestVector(byte[] seed, byte[] keyInfo, byte[] secretKey, byte[] publicKey, byte[] input,
		byte[] blind, byte[] blindedElement, byte[] evaluationElement, byte[] proof, byte[] proofRandomScalar, byte[] output) {}

	private static final RFC9497TestVector[] RFC9497TestVectors = new RFC9497TestVector[]{
		//
		new RFC9497TestVector(
			Hex.decode("a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3"),
			Hex.decode("74657374206b6579"),
			Hex.decode("051646b9e6e7a71ae27c1e1d0b87b4381db6d3595eeeb1adb41579adbf992f4278f9016eafc944edaa2b43183581779d"),
			Hex.decode("031d689686c611991b55f1a1d8f4305ccd6cb719446f660a30db61b7aa87b46acf59b7c0d4a9077b3da21c25dd482229a0"),
			Hex.decode("00"),
			Hex.decode("504650f53df8f16f6861633388936ea23338fa65ec36e0290022b48eb562889d89dbfa691d1cde91517fa222ed7ad364"),
			Hex.decode("02d338c05cbecb82de13d6700f09cb61190543a7b7e2c6cd4fca56887e564ea82653b27fdad383995ea6d02cf26d0e24d9"),
			Hex.decode("02a7bba589b3e8672aa19e8fd258de2e6aae20101c8d761246de97a6b5ee9cf105febce4327a326255a3c604f63f600ef6"),
			Hex.decode("bfc6cf3859127f5fe25548859856d6b7fa1c7459f0ba5712a806fc091a3000c42d8ba34ff45f32a52e40533efd2a03bc87f3bf4f9f58028297ccb9ccb18ae7182bcd1ef239df77e3be65ef147f3acf8bc9cbfc5524b702263414f043e3b7ca2e"),
			Hex.decode("803d955f0e073a04aa5d92b3fb739f56f9db001266677f62c095021db018cd8cbb55941d4073698ce45c405d1348b7b1"),
			Hex.decode("3333230886b562ffb8329a8be08fea8025755372817ec969d114d1203d026b4a622beab60220bf19078bca35a529b35c")
		),
		//
		new RFC9497TestVector(
			Hex.decode("a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3"),
			Hex.decode("74657374206b6579"),
			Hex.decode("051646b9e6e7a71ae27c1e1d0b87b4381db6d3595eeeb1adb41579adbf992f4278f9016eafc944edaa2b43183581779d"),
			Hex.decode("031d689686c611991b55f1a1d8f4305ccd6cb719446f660a30db61b7aa87b46acf59b7c0d4a9077b3da21c25dd482229a0"),
			Hex.decode("5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"),
			Hex.decode("504650f53df8f16f6861633388936ea23338fa65ec36e0290022b48eb562889d89dbfa691d1cde91517fa222ed7ad364"),
			Hex.decode("02f27469e059886f221be5f2cca03d2bdc61e55221721c3b3e56fc012e36d31ae5f8dc058109591556a6dbd3a8c69c433b"),
			Hex.decode("03f16f903947035400e96b7f531a38d4a07ac89a80f89d86a1bf089c525a92c7f4733729ca30c56ce78b1ab4f7d92db8b4"),
			Hex.decode("d005d6daaad7571414c1e0c75f7e57f2113ca9f4604e84bc90f9be52da896fff3bee496dcde2a578ae9df315032585f801fb21c6080ac05672b291e575a40295b306d967717b28e08fcc8ad1cab47845d16af73b3e643ddcc191208e71c64630"),
			Hex.decode("803d955f0e073a04aa5d92b3fb739f56f9db001266677f62c095021db018cd8cbb55941d4073698ce45c405d1348b7b1"),
			Hex.decode("b91c70ea3d4d62ba922eb8a7d03809a441e1c3c7af915cbc2226f485213e895942cd0f8580e6d99f82221e66c40d274f")
		),
	};

	@Test
	void testRFC9497TestVectors() {
		final var voprf = ECCurveVoprf.createP384();
		for (final var vector : RFC9497TestVectors) {
			final var keypair = assertDoesNotThrow(() -> voprf.deriveKeyPair(vector.seed(), vector.keyInfo()));
			assertArrayEquals(vector.secretKey(), keypair.secretKey(), "secret key");
			assertArrayEquals(vector.publicKey(), keypair.publicKey(), "public key");

			final var blindResult = assertDoesNotThrow(() -> voprf.blind(vector.input(), vector.blind()));
			assertArrayEquals(vector.blindedElement(), voprf.encodeElement(blindResult.blindedElement()), "blindedElement");

			final var blindEvaluateResult = assertDoesNotThrow(() -> voprf.blindEvaluate(keypair.secretKey(), keypair.publicKey(), blindResult.blindedElement(), vector.proofRandomScalar()));
			assertArrayEquals(vector.evaluationElement(), voprf.encodeElement(blindEvaluateResult.evaluatedElement()), "evaluatedElement");
			assertArrayEquals(vector.proof(), blindEvaluateResult.proof(), "proof");

			final var finalizeResult = assertDoesNotThrow(() -> voprf.finalize(vector.input(), blindResult.blind(), blindEvaluateResult.evaluatedElement(),
				blindResult.blindedElement(), vector.publicKey(), voprf.decodeProof(vector.proof())));
			assertArrayEquals(vector.output(), finalizeResult, "finalize output");

			final var evaluateResult = assertDoesNotThrow(() -> voprf.evaluate(keypair.secretKey(), vector.input()));
			assertArrayEquals(vector.output(), evaluateResult, "evaluate output");
		}
	}

}
