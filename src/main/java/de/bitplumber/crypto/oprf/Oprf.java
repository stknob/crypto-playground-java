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
 */
public interface Oprf<S, E, BR> {
	public KeyPair deriveKeyPair(byte[] seed, byte[] info) throws Exception;
	public KeyPair randomKeyPair();

	public byte[] encodeElement(E element);
	public E decodeElement(byte[] input) throws Exception;

	public byte[] encodeScalar(S scalar);
	public S decodeScalar(byte[] input) throws Exception;
	public S randomScalar();

	public BR blind(byte[] input) throws Exception;
	public E blindEvaluate(byte[] serverSecretKey, E blindedElement) throws Exception;
	public byte[] finalize(byte[] input, S blind, E evaluatedElement) throws Exception;
	public byte[] evaluate(byte[] serverSecretKey, byte[] input) throws Exception;
}
