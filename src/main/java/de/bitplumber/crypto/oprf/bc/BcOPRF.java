/**
 * RFC 9497 OPRF implementation for Bouncy Castle EC
 *
 * Copyright (c) 2025 Stefan Knoblich <stkn@bitplumber.de>
 *
 * SPDX-License-Identifier: MIT
 */
package de.bitplumber.crypto.oprf.bc;

import java.nio.charset.StandardCharsets;
import java.util.Objects;

import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;

import de.bitplumber.crypto.oprf.bc.BcOPRFSuite.ECScalar;
import de.bitplumber.crypto.oprf.*;

public class BcOPRF implements OPRF<ECScalar, ECPoint, BcOPRF.BlindResult> {
	public static record BlindResult(ECScalar blind, ECPoint blindedElement) {}

	private final BcOPRFSuite suite;
	private final byte[] context;

	private BcOPRF(final BcOPRFSuite suite) {
		this.suite = suite;
		this.context = Arrays.concatenate(new byte[][]{
			Labels.CONTEXT_PREFIX, Modes.OPRF,
			("-" + suite.getName()).getBytes(StandardCharsets.UTF_8),
		});
	}

	public static BcOPRF createP256() {
		return new BcOPRF(BcOPRFSuite.createP256());
	}

	public static BcOPRF createP384() {
		return new BcOPRF(BcOPRFSuite.createP384());
	}

	public static BcOPRF createP521() {
		return new BcOPRF(BcOPRFSuite.createP521());
	}

	public static BcOPRF createSecp256k1() {
		return new BcOPRF(BcOPRFSuite.createSecp256k1());
	}

	public OPRFKeyPair randomKeyPair() {
		return suite.randomKeyPair();
	}

	public OPRFKeyPair deriveKeyPair(byte[] seed, byte[] info) throws Exception {
		return suite.deriveKeyPair(seed, info, context);
	}

	public byte[] encodeElement(ECPoint element) {
		return suite.encodeElement(element);
	}

	public ECPoint decodeElement(byte[] encoded) {
		return suite.decodeElement(encoded);
	}

	public ECScalar randomScalar() {
		return suite.randomScalar();
	}

	public byte[] encodeScalar(ECScalar scalar) {
		return suite.encodeScalar(scalar);
	}

	public ECScalar decodeScalar(byte[] encoded) {
		return suite.decodeScalar(encoded);
	}

	private BlindResult doBlind(byte[] input, ECScalar blind) throws Exception {
		final var inputElement = suite.hashToGroup(input, null, context);
		if (inputElement.isInfinity() || !inputElement.isValid())
			throw new IllegalArgumentException("InvalidInputError");

		final var blindedElement = inputElement.multiply(blind.toBigInteger());
		return new BlindResult(blind, blindedElement);
	}

	protected BlindResult blind(byte[] input, byte[] blind) throws Exception {
		Objects.requireNonNull(blind, "Mandatory parameter 'blind' missing");
		return doBlind(input, suite.decodeScalar(blind));
	}

	public BlindResult blind(byte[] input) throws Exception {
		return doBlind(input, suite.randomScalar());
	}

	public ECPoint blindEvaluate(byte[] serverSecretKey, ECPoint blindedElement) throws Exception {
		final var skS = suite.decodeScalar(serverSecretKey);
		return blindedElement.multiply(skS.toBigInteger());
	}

	public byte[] finalize(byte[] input, ECScalar blind, ECPoint evaluatedElement) throws Exception {
		final var invBlind = suite.invertScalar(blind);
		final var n = evaluatedElement.multiply(invBlind.toBigInteger());
		final var unblindedElement = suite.encodeElement(n);

		return suite.hash(Arrays.concatenate(new byte[][]{
			suite.I2OSP(input.length, 2), input,
			suite.I2OSP(unblindedElement.length, 2), unblindedElement,
			Labels.FINALIZE
		}));
	}

	public byte[] evaluate(byte[] serverSecretKey, byte[] input) throws Exception {
		final var inputElement = suite.hashToGroup(input, null, context);
		if (inputElement.isInfinity() || !inputElement.isValid())
			throw new IllegalArgumentException("InvalidInputError");

		final var skS = suite.decodeScalar(serverSecretKey);
		final var evaluatedElement = inputElement.multiply(skS.toBigInteger());
		final var issuedElement = suite.encodeElement(evaluatedElement);

		return suite.hash(Arrays.concatenate(new byte[][]{
			suite.I2OSP(input.length, 2), input,
			suite.I2OSP(issuedElement.length, 2), issuedElement,
			Labels.FINALIZE
		}));
	}
}
