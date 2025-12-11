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
public interface Poprf<S, E, BR, BER, P> {
	public KeyPair deriveKeyPair(byte[] seed, byte[] info) throws Exception;
	public KeyPair randomKeyPair();

	public byte[] encodeElement(E element);
	public E decodeElement(byte[] input) throws Exception;

	public byte[] encodeScalar(S scalar);
	public S decodeScalar(byte[] input) throws Exception;
	public S randomScalar();

	public BR blind(byte[] input, byte[] info, byte[] serverPublicKey) throws Exception;
	public BER blindEvaluate(byte[] serverSecretKey, E blindedElement, byte[] info) throws Exception;
	public byte[] finalize(byte[] input, S blind, E evaluatedElement, E blindedElement, P proof, byte[] info, E tweakedKey) throws Exception;
	public byte[] evaluate(byte[] serverSecretKey, byte[] input, byte[] info) throws Exception;
}
