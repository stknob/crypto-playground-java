/**
 * RFC 9497 OPRF implementation for Bouncy Castle EC
 *
 * Copyright (c) 2025 Stefan Knoblich <stkn@bitplumber.de>
 *
 * SPDX-License-Identifier: MIT
 */
package de.bitplumber.crypto.oprf.bc;

import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

class P384PoprfTest extends GenericOprfTestBase {
	private static final RFC9497PoprfTestVector[] POPRF_TEST_VECTORS = new RFC9497PoprfTestVector[]{
		// ristretto255-SHA512 - POPRF - Test Vector 1, Batch Size 1
		new RFC9497PoprfTestVector(
			Hex.decode("a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3"),
			Hex.decode("74657374206b6579"),
			Hex.decode("5b2690d6954b8fbb159f19935d64133f12770c00b68422559c65431942d721ff79d47d7a75906c30b7818ec0f38b7fb2"),
			Hex.decode("02f00f0f1de81e5d6cf18140d4926ffdc9b1898c48dc49657ae36eb1e45deb8b951aaf1f10c82d2eaa6d02aafa3f10d2b6"),
			Hex.decode("7465737420696e666f"),
			Hex.decode("00"),
			Hex.decode("504650f53df8f16f6861633388936ea23338fa65ec36e0290022b48eb562889d89dbfa691d1cde91517fa222ed7ad364"),
			Hex.decode("03859b36b95e6564faa85cd3801175eda2949707f6aa0640ad093cbf8ad2f58e762f08b56b2a1b42a64953aaf49cbf1ae3"),
			Hex.decode("0220710e2e00306453f5b4f574cb6a512453f35c45080d09373e190c19ce5b185914fbf36582d7e0754bb7c8b683205b91"),
			Hex.decode("82a17ef41c8b57f1e3122311b4d5cd39a63df0f67443ef18d961f9b659c1601ced8d3c64b294f604319ca80230380d437a49c7af0d620e22116669c008ebb767d90283d573b49cdb49e3725889620924c2c4b047a2a6225a3ba27e640ebddd33"),
			Hex.decode("803d955f0e073a04aa5d92b3fb739f56f9db001266677f62c095021db018cd8cbb55941d4073698ce45c405d1348b7b1"),
			Hex.decode("0188653cfec38119a6c7dd7948b0f0720460b4310e40824e048bf82a16527303ed449a08caf84272c3bbc972ede797df")
		),
		// ristretto255-SHA512 - POPRF - Test Vector 2, Batch Size 1
		new RFC9497PoprfTestVector(
			Hex.decode("a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3"),
			Hex.decode("74657374206b6579"),
			Hex.decode("5b2690d6954b8fbb159f19935d64133f12770c00b68422559c65431942d721ff79d47d7a75906c30b7818ec0f38b7fb2"),
			Hex.decode("02f00f0f1de81e5d6cf18140d4926ffdc9b1898c48dc49657ae36eb1e45deb8b951aaf1f10c82d2eaa6d02aafa3f10d2b6"),
			Hex.decode("7465737420696e666f"),
			Hex.decode("5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"),
			Hex.decode("504650f53df8f16f6861633388936ea23338fa65ec36e0290022b48eb562889d89dbfa691d1cde91517fa222ed7ad364"),
			Hex.decode("03f7efcb4aaf000263369d8a0621cb96b81b3206e99876de2a00699ed4c45acf3969cd6e2319215395955d3f8d8cc1c712"),
			Hex.decode("034993c818369927e74b77c400376fd1ae29b6ac6c6ddb776cf10e4fbc487826531b3cf0b7c8ca4d92c7af90c9def85ce6"),
			Hex.decode("693471b5dff0cd6a5c00ea34d7bf127b2795164e3bdb5f39a1e5edfbd13e443bc516061cd5b8449a473c2ceeccada9f3e5b57302e3d7bc5e28d38d6e3a3056e1e73b6cc030f5180f8a1ffa45aa923ee66d2ad0a07b500f2acc7fb99b5506465c"),
			Hex.decode("803d955f0e073a04aa5d92b3fb739f56f9db001266677f62c095021db018cd8cbb55941d4073698ce45c405d1348b7b1"),
			Hex.decode("ff2a527a21cc43b251a567382677f078c6e356336aec069dea8ba36995343ca3b33bb5d6cf15be4d31a7e6d75b30d3f5")
		),
	};

	@Test
	void testPoprfTestVectors() { //NOSONAR
		final var poprf = ECCurvePoprf.createP384();
		runTestVectors(poprf, POPRF_TEST_VECTORS);
	}
}
