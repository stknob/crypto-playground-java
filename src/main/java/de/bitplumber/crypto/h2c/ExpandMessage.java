/**
 * RFC 9380 Hash-to-Curve implementation for Bouncy-Castle EC
 *
 * Copyright (c) 2025 Stefan Knoblich <stkn@bitplumber.de>
 *
 * SPDX-License-Identifier: MIT
 */
package de.bitplumber.crypto.h2c;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.crypto.Xof;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Bytes;

public class ExpandMessage {
	private ExpandMessage() { /* */ }

	protected static byte[] hashXMD(ExtendedDigest md, byte[] input) {
		final var output = new byte[md.getDigestSize()];
		md.reset();
		md.update(input, 0, input.length);
		md.doFinal(output, 0);
		return output;
	}

	protected static byte[] hashXOF(Xof xof, byte[] input, int lengthInBytes) {
		final var output = new byte[lengthInBytes];
		xof.reset();
		xof.update(input, 0, input.length);
		xof.doFinal(output, 0);
		return output;
	}

	protected static byte[] I2OSP(long input, int size) {	// NOSONAR
		return BigIntegers.asUnsignedByteArray(size, BigInteger.valueOf(input));
	}

	/**
	 *
	 * @param xmd MessageDigest hash instance
	 * @param msg Input message to hash
	 * @param dst Domain separation tag
	 * @param lengthInBytes Output length
	 * @return
	 */
	public static byte[] expandMessageXMD(ExtendedDigest xmd, byte[] msg, byte[] dst, int lengthInBytes) {
		final var hashOutputSize = xmd.getDigestSize();
		final var hashBlockSize  = xmd.getByteLength();
		if (dst.length > 255) {
			dst = hashXMD(xmd, Arrays.concatenate("H2C-OVERSIZE-DST-".getBytes(StandardCharsets.UTF_8), dst));
		}

		final var ell = Math.ceilDiv(lengthInBytes, hashOutputSize);
		if (lengthInBytes > 65535 || ell > 255) {
			throw new IllegalArgumentException("expand_message_xmd: Invalid lengthInBytes");
		}

		final var dstPrime = Arrays.concatenate(dst, I2OSP(dst.length, 1));
		final var lengthInBytesStr = I2OSP(lengthInBytes, 2);
		final var zPad = I2OSP(0, hashBlockSize);

		final var b = new byte[ell][];
		final var b0 = hashXMD(xmd, Arrays.concatenate(new byte[][]{ zPad, msg, lengthInBytesStr, I2OSP(0, 1), dstPrime }));
		b[0] = hashXMD(xmd, Arrays.concatenate(new byte[][]{ b0, I2OSP(1, 1), dstPrime }));

		if (ell > 1) {
			final var tmp = new byte[hashOutputSize];
			for (int i = 1; i < ell; i++) {
				Bytes.xor(b0.length, b0, b[i - 1], tmp);
				b[i] = hashXMD(xmd, Arrays.concatenate(tmp, I2OSP(i + 1l, 1), dstPrime));
			}
		}

		final var output = Arrays.concatenate(b);
		return Arrays.copyOfRange(output, 0, lengthInBytes);
	}

	/**
	 *
	 * @param xof XOF hash instance
	 * @param msg Input message to hash
	 * @param dst Domain separation tag
	 * @param lengthInBytes Output length
	 * @param k Security level of the elliptic curve (in bits)
	 * @return
	 *
	 */
	public static byte[] expandMessageXOF(Xof xof, byte[] msg, byte[] dst, int lengthInBytes, int k) {
		if (dst.length > 255) {
			dst = hashXOF(xof, Arrays.concatenate("H2C-OVERSIZE-DST-".getBytes(StandardCharsets.UTF_8), dst), Math.ceilDiv(2 * k, 8));
		}

		if (lengthInBytes > 65535) {
			throw new IllegalArgumentException("expand_message_xof: Invalid lengthInBytes");
		}

		final var dstPrime = Arrays.concatenate(dst, I2OSP(dst.length, 1));
		final var msgPrime = Arrays.concatenate(msg, I2OSP(lengthInBytes, 2), dstPrime);
		return hashXOF(xof, msgPrime, lengthInBytes);
	}
}
