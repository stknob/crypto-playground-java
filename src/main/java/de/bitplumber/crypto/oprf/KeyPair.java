/**
 * RFC 9497 OPRF implementation for Bouncy Castle EC
 *
 * Copyright (c) 2025 Stefan Knoblich <stkn@bitplumber.de>
 *
 * SPDX-License-Identifier: MIT
 */
package de.bitplumber.crypto.oprf;

public record KeyPair(byte[] secretKey, byte[] publicKey) {}
