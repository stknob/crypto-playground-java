# Java Cryptography playground

### Disclaimer
:warning: This repository contains experimental implementations of various cryptographic protocols.<br>
The code has not been audited and may change at any time! __DO _NOT_ USE IN PRODUCTION!__

### Contents
- RFC 9830 - Hash to Curve / Encode to Curve / Hash to Field
    - Suites: P256-SHA256, P384-SHA384, P521-SHA512, secp256k1-SHA256

- RFC 9494 - Oblivious Pseudorandom Functions (OPRFs) Using Prime-Order Groups
    - Suites: Ristretto255-SHA512 (WIP: P256-SHA256, P384-SHA384, P521-SHA512)
	- Modes: OPRF, VOPRF, POPRF

- NOPAQUE - OPAQUE without PAKE
    - Suites: Ristretto255-SHA512
