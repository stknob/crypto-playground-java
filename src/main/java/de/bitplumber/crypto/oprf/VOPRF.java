/**
 * RFC 9497 OPRF implementation for Bouncy Castle EC
 *
 * Copyright (c) 2025 Stefan Knoblich <stkn@bitplumber.de>
 *
 * SPDX-License-Identifier: MIT
 */
package de.bitplumber.crypto.oprf;

/**
 * @param S Scalar type
 * @param E Field Element (= Point) type
 * @param BR Blind result type
 * @param BER BlindEvaluate result type
 * @param P Proof type
 */
public interface VOPRF<S, E, BR, BER, P> {
	public OPRFKeyPair deriveKeyPair(byte[] seed, byte[] info) throws Exception;
	public OPRFKeyPair randomKeyPair();

	public byte[] encodeElement(E element);
	public E decodeElement(byte[] input) throws Exception;

	public byte[] encodeScalar(S scalar);
	public S decodeScalar(byte[] input) throws Exception;
	public S randomScalar();

	public BR blind(byte[] input) throws Exception;
	public BER blindEvaluate(byte[] serverSecretKey, byte[] serverPublicKey, E blindedElement) throws Exception;
	public byte[] finalize(byte[] input, S blind, E evaluatedElement, E blindedElement, byte[] serverPublicKey, P proof) throws Exception;
	public byte[] evaluate(byte[] serverSecretKey, byte[] input) throws Exception;
}
