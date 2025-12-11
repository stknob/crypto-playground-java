/**
 * RFC 9497 OPRF implementation for Ristretto255
 *
 * Copyright (c) 2025 Stefan Knoblich <stkn@bitplumber.de>
 *
 * SPDX-License-Identifier: MIT
 */
package de.bitplumber.crypto.oprf.ristretto255;

import java.nio.charset.StandardCharsets;
import java.util.Objects;

import org.bouncycastle.util.Arrays;

import com.weavechain.curve25519.RistrettoElement;
import com.weavechain.curve25519.Scalar;

import de.bitplumber.crypto.oprf.Labels;
import de.bitplumber.crypto.oprf.Modes;
import de.bitplumber.crypto.oprf.VOPRF;

public class Ristretto255VOPRF extends AbstractRistretto255 implements VOPRF<Scalar, RistrettoElement, Ristretto255VOPRF.BlindResult, Ristretto255VOPRF.BlindEvaluateResult, AbstractRistretto255.Proof> {
	public static record BlindResult(Scalar blind, RistrettoElement blindedElement) {}
	public static final record BlindEvaluateResult(RistrettoElement evaluatedElement, byte[] proof) {}
	private final VoprfParameter params;

	private static final byte[] CONTEXT = Arrays.concatenate(new byte[][]{
		Labels.CONTEXT_PREFIX, Modes.VOPRF,
		("-" + SUITE_ID).getBytes(StandardCharsets.UTF_8),
	});

	protected byte[] context() {
		return CONTEXT;
	}

	public Ristretto255VOPRF() {
		this.params = DEFAULT_PARAMETER;
	}

	public Ristretto255VOPRF(VoprfParameter params) {
		this.params = params;
	}

	public static final VoprfParameter DEFAULT_PARAMETER = new VoprfParameter();
	public static final class VoprfParameter {
		protected byte[] proofRandomScalar;
		protected byte[] blindRandomScalar;

		public byte[] blindRandomScalar() {
			return blindRandomScalar;
		}

		public byte[] proofRandomScalar() {
			return proofRandomScalar;
		}

		/**
		 * Set a custom domain separation label for key derivation
		 * <strong>For unittests only!</strong>
		 * @param label
		 * @return
		 */
		public VoprfParameter withBlindRandomScalar(byte[] blindRandomScalar) {
			Objects.requireNonNull(blindRandomScalar, "blindRandomScalar");
			this.blindRandomScalar = blindRandomScalar;
			return this;
		}

		/**
		 * Set a custom domain separation label for key derivation
		 * <strong>For unittests only!</strong>
		 * @param label
		 * @return
		 */
		public VoprfParameter withProofRandomScalar(byte[] proofRandomScalar) {
			Objects.requireNonNull(proofRandomScalar, "proofRandomScalar");
			this.proofRandomScalar = proofRandomScalar;
			return this;
		}
	}

	private BlindResult doBlind(byte[] input, Scalar blind) throws Exception {
		final var inputElement = hashToGroup(input, null);
		if (RistrettoElement.IDENTITY.ctEquals(inputElement) == 1)
			throw new IllegalArgumentException("InvalidInputError");

		final var blindedElement = inputElement.multiply(blind);
		return new BlindResult(blind, blindedElement);
	}

	public BlindResult blind(byte[] input) throws Exception {
		return doBlind(input, params.blindRandomScalar() == null ? randomScalar() : decodeScalar(params.blindRandomScalar()));
	}

	public BlindEvaluateResult blindEvaluate(byte[] serverSecretKey, byte[] serverPublicKey, RistrettoElement blindedElement) throws Exception {
		final var skS = decodeScalar(serverSecretKey);
		final var pkS = decodeElement(serverPublicKey);
		final var evaluatedElement = blindedElement.multiply(skS);
		final var blindedElements  = new RistrettoElement[]{ blindedElement };
		final var evaluatedElements = new RistrettoElement[]{ evaluatedElement };
		final var proof = generateProof(skS, RistrettoElement.BASEPOINT, pkS, blindedElements, evaluatedElements,
			params.proofRandomScalar() == null ? null : decodeScalar(params.proofRandomScalar()));
		return new BlindEvaluateResult(evaluatedElement, proof.toByteArray());
	}

	public byte[] finalize(byte[] input, Scalar blind, RistrettoElement evaluatedElement, RistrettoElement blindedElement, byte[] serverPublicKey, Proof proof) throws Exception {
		final var pkS = decodeElement(serverPublicKey);
		final var blindedElements = new RistrettoElement[]{ blindedElement };
		final var evaluatedElements = new RistrettoElement[]{ evaluatedElement };
		if (!verifyProof(RistrettoElement.BASEPOINT, pkS, blindedElements, evaluatedElements, proof))
			throw new Exception("Failed to verify proof");

		final var invBlind = blind.invert();
		final var n = evaluatedElement.multiply(invBlind);
		final var unblindedElement = encodeElement(n);
		return hash(Arrays.concatenate(new byte[][]{
			I2OSP(input.length, 2), input,
			I2OSP(unblindedElement.length, 2), unblindedElement,
			Labels.FINALIZE
		}));
	}

	public byte[] evaluate(byte[] serverSecretKey, byte[] input) throws Exception {
		final var inputElement = hashToGroup(input, null);
		if (RistrettoElement.IDENTITY.ctEquals(inputElement) == 1)
			throw new IllegalArgumentException("InvalidInputError");

		final var skS = decodeScalar(serverSecretKey);
		final var evaluatedElement = inputElement.multiply(skS);
		final var issuedElement = encodeElement(evaluatedElement);

		return hash(Arrays.concatenate(new byte[][]{
			I2OSP(input.length, 2), input,
			I2OSP(issuedElement.length, 2), issuedElement,
			Labels.FINALIZE
		}));
	}
}
