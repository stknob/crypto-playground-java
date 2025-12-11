/**
 * RFC 9497 OPRF implementation for Bouncy Castle EC
 *
 * Copyright (c) 2025 Stefan Knoblich <stkn@bitplumber.de>
 *
 * SPDX-License-Identifier: MIT
 */
package de.bitplumber.crypto.oprf;

import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

class P256PoprfTest extends GenericOprfTestBase {
	private static final RFC9497PoprfTestVector[] POPRF_TEST_VECTORS = new RFC9497PoprfTestVector[]{
		// ristretto255-SHA512 - POPRF - Test Vector 1, Batch Size 1
		new RFC9497PoprfTestVector(
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
		new RFC9497PoprfTestVector(
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
	void testPoprfTestVectors() { //NOSONAR
		final var poprf = ECCurvePoprf.createP256();
		runTestVectors(poprf, POPRF_TEST_VECTORS);
	}
}
