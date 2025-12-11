/**
 * RFC 9497 OPRF implementation for Ristretto255
 *
 * Copyright (c) 2025 Stefan Knoblich <stkn@bitplumber.de>
 *
 * SPDX-License-Identifier: MIT
 */
package de.bitplumber.crypto.oprf.ristretto255;

import java.nio.charset.StandardCharsets;

import org.bouncycastle.util.Arrays;

import com.weavechain.curve25519.RistrettoElement;
import com.weavechain.curve25519.Scalar;

import de.bitplumber.crypto.oprf.Labels;
import de.bitplumber.crypto.oprf.Modes;
import de.bitplumber.crypto.oprf.Oprf;

public class Ristretto255Oprf extends AbstractRistretto255 implements Oprf<Scalar, RistrettoElement, Ristretto255Oprf.BlindResult> {
	public static record BlindResult(Scalar blind, RistrettoElement blindedElement) {}

	private static final byte[] CONTEXT = Arrays.concatenate(new byte[][]{
		Labels.CONTEXT_PREFIX, Modes.OPRF,
		("-" + SUITE_ID).getBytes(StandardCharsets.UTF_8),
	});

	protected byte[] context() {
		return CONTEXT;
	}

	private BlindResult doBlind(byte[] input, Scalar blind) throws Exception {
		final var inputElement = hashToGroup(input, null);
		if (RistrettoElement.IDENTITY.ctEquals(inputElement) == 1)
			throw new IllegalArgumentException("InvalidInputError");

		final var blindedElement = inputElement.multiply(blind);
		return new BlindResult(blind, blindedElement);
	}

	public BlindResult blind(byte[] input, byte[] blind) throws Exception {
		return doBlind(input, blind == null ? randomScalar() : decodeScalar(blind));
	}

	public BlindResult blind(byte[] input) throws Exception {
		return doBlind(input, randomScalar());
	}

	public RistrettoElement blindEvaluate(byte[] serverSecretKey, RistrettoElement blindedElement) throws Exception {
		final var skS = decodeScalar(serverSecretKey);
		return blindedElement.multiply(skS);
	}

	public byte[] finalize(byte[] input, Scalar blind, RistrettoElement evaluatedElement) throws Exception {
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
