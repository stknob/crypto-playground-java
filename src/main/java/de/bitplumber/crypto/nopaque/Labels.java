package de.bitplumber.crypto.nopaque;

import java.nio.charset.StandardCharsets;

public abstract class Labels {
	public static final byte[] NOPAQUE_DERIVE_KEYPAIR = "NOPAQUE-DeriveKeyPair".getBytes(StandardCharsets.UTF_8);
	public static final byte[] NOPAQUE_DERIVE_DH_KEYPAIR = "NOPAQUE-DeriveDiffieHellmanKeyPair".getBytes(StandardCharsets.UTF_8);
	public static final byte[] MASKING_KEY = "MaskingKey".getBytes(StandardCharsets.UTF_8);
	public static final byte[] EXPORT_KEY = "ExportKey".getBytes(StandardCharsets.UTF_8);
	public static final byte[] AUTH_KEY = "AuthKey".getBytes(StandardCharsets.UTF_8);
	public static final byte[] PRIVATE_KEY = "PrivateKey".getBytes(StandardCharsets.UTF_8);
	public static final byte[] CREDENTIAL_RESPONSE_PAD = "CredentialResponsePad".getBytes(StandardCharsets.UTF_8);
	public static final byte[] OPRF_KEY = "OprfKey".getBytes(StandardCharsets.UTF_8);

	private Labels() {}
}
