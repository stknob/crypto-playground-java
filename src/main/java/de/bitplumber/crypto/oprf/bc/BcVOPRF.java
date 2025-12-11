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
import de.bitplumber.crypto.oprf.bc.BcOPRFSuite.Proof;
import de.bitplumber.crypto.oprf.*;

public class BcVOPRF implements VOPRF<ECScalar, ECPoint, BcVOPRF.BlindResult, BcVOPRF.BlindEvaluateResult, BcOPRFSuite.Proof> {
	public static record BlindResult(ECScalar blind, ECPoint blindedElement) {}
	public static final record BlindEvaluateResult(ECPoint evaluatedElement, byte[] proof) {}

    private final BcOPRFSuite suite;
	private final byte[] context;

	public BcVOPRF(final BcOPRFSuite suite) {
        this.suite  = suite;
		this.context = Arrays.concatenate(new byte[][]{
			Labels.CONTEXT_PREFIX, Modes.VOPRF,
			("-" + suite.getName()).getBytes(StandardCharsets.UTF_8),
		});
	}

	public static BcVOPRF createP256() {
		return new BcVOPRF(BcOPRFSuite.createP256());
	}

	public static BcVOPRF createP384() {
		return new BcVOPRF(BcOPRFSuite.createP384());
	}

	public static BcVOPRF createP521() {
		return new BcVOPRF(BcOPRFSuite.createP521());
	}

	public static BcVOPRF createSecp256k1() {
		return new BcVOPRF(BcOPRFSuite.createSecp256k1());
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

	public Proof decodeProof(byte[] encoded) {
		return Proof.fromBytes(suite, encoded);
	}

	public byte[] encodeProof(Proof proof) {
		return proof.toByteArray();
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

	private BlindEvaluateResult doBlindEvaluate(byte[] serverSecretKey, byte[] serverPublicKey, ECPoint blindedElement, ECScalar proofRandomScalar) throws Exception {
		final var skS = suite.decodeScalar(serverSecretKey);
		final var pkS = suite.decodeElement(serverPublicKey);
		final var evaluatedElement = blindedElement.multiply(skS.toBigInteger());
		final var blindedElements  = new ECPoint[]{ blindedElement };
		final var evaluatedElements = new ECPoint[]{ evaluatedElement };
		final var proof = suite.generateProof(skS, suite.getG(), pkS, blindedElements, evaluatedElements, proofRandomScalar, context);
		return new BlindEvaluateResult(evaluatedElement, encodeProof(proof));
	}

	protected BlindEvaluateResult blindEvaluate(byte[] serverSecretKey, byte[] serverPublicKey, ECPoint blindedElement, byte[] proofRandomScalar) throws Exception {
		Objects.requireNonNull(proofRandomScalar, "Mandatory parameter 'proofRandomScalar' missing");
		return doBlindEvaluate(serverSecretKey, serverPublicKey, blindedElement, suite.decodeScalar(proofRandomScalar));
	}

	public BlindEvaluateResult blindEvaluate(byte[] serverSecretKey, byte[] serverPublicKey, ECPoint blindedElement) throws Exception {
		return doBlindEvaluate(serverSecretKey, serverPublicKey, blindedElement, null);
	}

	public byte[] finalize(byte[] input, ECScalar blind, ECPoint evaluatedElement, ECPoint blindedElement, byte[] serverPublicKey, Proof proof) throws Exception {
		final var pkS = suite.decodeElement(serverPublicKey);
		final var blindedElements = new ECPoint[]{ blindedElement };
		final var evaluatedElements = new ECPoint[]{ evaluatedElement };
		if (!suite.verifyProof(suite.getG(), pkS, blindedElements, evaluatedElements, proof, context))
			throw new Exception("Failed to verify proof");

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
