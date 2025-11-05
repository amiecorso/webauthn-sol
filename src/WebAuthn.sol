// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {FCL_ecdsa} from "FreshCryptoLib/FCL_ecdsa.sol";
import {FCL_Elliptic_ZZ} from "FreshCryptoLib/FCL_elliptic.sol";
import {Base64} from "openzeppelin-contracts/contracts/utils/Base64.sol";
import {LibString} from "solady/utils/LibString.sol";

/// @title WebAuthn
///
/// @notice A library for verifying WebAuthn Authentication Assertions, built off the work
///         of Daimo.
///
/// @dev Attempts to use the RIP-7212 precompile for signature verification.
///      If precompile verification fails, it falls back to FreshCryptoLib.
///
/// @author Coinbase (https://github.com/base-org/webauthn-sol)
/// @author Daimo (https://github.com/daimo-eth/p256-verifier/blob/master/src/WebAuthn.sol)
library WebAuthn {
    using LibString for string;

    struct WebAuthnAuth {
        /// @dev The WebAuthn authenticator data.
        ///      See https://www.w3.org/TR/webauthn-2/#dom-authenticatorassertionresponse-authenticatordata.
        bytes authenticatorData;
        /// @dev The WebAuthn client data JSON.
        ///      See https://www.w3.org/TR/webauthn-2/#dom-authenticatorresponse-clientdatajson.
        string clientDataJSON;
        /// @dev The index at which "challenge":"..." occurs in `clientDataJSON`.
        uint256 challengeIndex;
        /// @dev The index at which "type":"..." occurs in `clientDataJSON`.
        uint256 typeIndex;
        /// @dev The r value of secp256r1 signature
        uint256 r;
        /// @dev The s value of secp256r1 signature
        uint256 s;
    }

    /// @dev Bit 0 of the authenticator data struct, corresponding to the "User Present" bit.
    ///      See https://www.w3.org/TR/webauthn-2/#flags.
    bytes1 private constant _AUTH_DATA_FLAGS_UP = 0x01;

    /// @dev Bit 2 of the authenticator data struct, corresponding to the "User Verified" bit.
    ///      See https://www.w3.org/TR/webauthn-2/#flags.
    bytes1 private constant _AUTH_DATA_FLAGS_UV = 0x04;

    /// @dev Secp256r1 curve order / 2 used as guard to prevent signature malleability issue.
    uint256 private constant _P256_N_DIV_2 = FCL_Elliptic_ZZ.n / 2;

    /// @dev The precompiled contract address to use for signature verification in the “secp256r1” elliptic curve.
    ///      See https://github.com/ethereum/RIPs/blob/master/RIPS/rip-7212.md.
    address private constant _VERIFIER = address(0x100);

    /// @dev The expected type (hash) in the client data JSON when verifying assertion signatures.
    ///      See https://www.w3.org/TR/webauthn-2/#dom-collectedclientdata-type
    bytes32 private constant _EXPECTED_TYPE_HASH = keccak256('"type":"webauthn.get"');

    // Known-valid P-256 test vector used to disambiguate precompile presence vs invalid signature.
    // Values are from Wycheproof and match OpenZeppelin's probe.
    bytes32 private constant _PROBE_H = 0xbb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023;
    bytes32 private constant _PROBE_R = bytes32(uint256(5));
    bytes32 private constant _PROBE_S = bytes32(uint256(1));
    bytes32 private constant _PROBE_QX = 0xa71af64de5126a4a4e02b7922d66ce9415ce88a4c9d25514d91082c8725ac957;
    bytes32 private constant _PROBE_QY = 0x5d47723c8fbe580bb369fec9c2665d8e30a435b9932645482e7c9f11e872296b;

    ///
    /// @notice Verifies a Webauthn Authentication Assertion as described
    /// in https://www.w3.org/TR/webauthn-2/#sctn-verifying-assertion.
    ///
    /// @dev We do not verify all the steps as described in the specification, only ones relevant to our context.
    ///      Please carefully read through this list before usage.
    ///
    ///      Specifically, we do verify the following:
    ///         - Verify that authenticatorData (which comes from the authenticator, such as iCloud Keychain) indicates
    ///           a well-formed assertion with the user present bit set. If `requireUV` is set, checks that the authenticator
    ///           enforced user verification. User verification should be required if, and only if, options.userVerification
    ///           is set to required in the request.
    ///         - Verifies that the client JSON is of type "webauthn.get", i.e. the client was responding to a request to
    ///           assert authentication.
    ///         - Verifies that the client JSON contains the requested challenge.
    ///         - Verifies that (r, s) constitute a valid signature over both the authenicatorData and client JSON, for public
    ///            key (x, y).
    ///
    ///      We make some assumptions about the particular use case of this verifier, so we do NOT verify the following:
    ///         - Does NOT verify that the origin in the `clientDataJSON` matches the Relying Party's origin: tt is considered
    ///           the authenticator's responsibility to ensure that the user is interacting with the correct RP. This is
    ///           enforced by most high quality authenticators properly, particularly the iCloud Keychain and Google Password
    ///           Manager were tested.
    ///         - Does NOT verify That `topOrigin` in `clientDataJSON` is well-formed: We assume it would never be present, i.e.
    ///           the credentials are never used in a cross-origin/iframe context. The website/app set up should disallow
    ///           cross-origin usage of the credentials. This is the default behaviour for created credentials in common settings.
    ///         - Does NOT verify that the `rpIdHash` in `authenticatorData` is the SHA-256 hash of the RP ID expected by the Relying
    ///           Party: this means that we rely on the authenticator to properly enforce credentials to be used only by the correct RP.
    ///           This is generally enforced with features like Apple App Site Association and Google Asset Links. To protect from
    ///           edge cases in which a previously-linked RP ID is removed from the authorised RP IDs, we recommend that messages
    ///           signed by the authenticator include some expiry mechanism.
    ///         - Does NOT verify the credential backup state: this assumes the credential backup state is NOT used as part of Relying
    ///           Party business logic or policy.
    ///         - Does NOT verify the values of the client extension outputs: this assumes that the Relying Party does not use client
    ///           extension outputs.
    ///         - Does NOT verify the signature counter: signature counters are intended to enable risk scoring for the Relying Party.
    ///           This assumes risk scoring is not used as part of Relying Party business logic or policy.
    ///         - Does NOT verify the attestation object: this assumes that response.attestationObject is NOT present in the response,
    ///           i.e. the RP does not intend to verify an attestation.
    ///
    /// @param challenge The challenge that was provided by the relying party.
    /// @param requireUV A boolean indicating whether user verification is required.
    /// @param webAuthnAuth The `WebAuthnAuth` struct.
    /// @param x The x coordinate of the public key.
    /// @param y The y coordinate of the public key.
    ///
    /// @return `true` if the authentication assertion passed validation, else `false`.
    function verify(bytes memory challenge, bool requireUV, WebAuthnAuth memory webAuthnAuth, uint256 x, uint256 y)
        internal
        view
        returns (bool)
    {
        if (webAuthnAuth.s > _P256_N_DIV_2) {
            // guard against signature malleability
            return false;
        }

        // 11. Verify that the value of C.type is the string webauthn.get.
        // bytes("type":"webauthn.get").length = 21
        string memory _type = webAuthnAuth.clientDataJSON.slice(webAuthnAuth.typeIndex, webAuthnAuth.typeIndex + 21);
        if (keccak256(bytes(_type)) != _EXPECTED_TYPE_HASH) {
            return false;
        }

        // 12. Verify that the value of C.challenge equals the base64url encoding of options.challenge.
        bytes memory expectedChallenge = bytes(string.concat('"challenge":"', Base64.encodeURL(challenge), '"'));
        string memory actualChallenge =
            webAuthnAuth.clientDataJSON.slice(webAuthnAuth.challengeIndex, webAuthnAuth.challengeIndex + expectedChallenge.length);
        if (keccak256(bytes(actualChallenge)) != keccak256(expectedChallenge)) {
            return false;
        }

        // Skip 13., 14., 15.

        // 16. Verify that the UP bit of the flags in authData is set.
        if (webAuthnAuth.authenticatorData[32] & _AUTH_DATA_FLAGS_UP != _AUTH_DATA_FLAGS_UP) {
            return false;
        }

        // 17. If user verification is required for this assertion, verify that the User Verified bit of the flags in
        // authData is set.
        if (requireUV && (webAuthnAuth.authenticatorData[32] & _AUTH_DATA_FLAGS_UV) != _AUTH_DATA_FLAGS_UV) {
            return false;
        }

        // skip 18.

        // 19. Let hash be the result of computing a hash over the cData using SHA-256.
        bytes32 clientDataJSONHash = sha256(bytes(webAuthnAuth.clientDataJSON));

        // 20. Using credentialPublicKey, verify that sig is a valid signature over the binary concatenation of authData
        // and hash.
        bytes32 messageHash = sha256(abi.encodePacked(webAuthnAuth.authenticatorData, clientDataJSONHash));
        // Attempt RIP-7212 precompile; if ambiguous/false, probe with known-valid vector to
        // detect precompile presence and avoid unnecessary software fallback when present.
        if (_rip7212(messageHash, webAuthnAuth.r, webAuthnAuth.s, x, y)) {
            return true;
        }

        if (_rip7212(_PROBE_H, uint256(_PROBE_R), uint256(_PROBE_S), uint256(_PROBE_QX), uint256(_PROBE_QY))) {
            // Precompile is present; original signature invalid.
            return false;
        }

        // Precompile absent; fall back to FreshCryptoLib's software verifier.
        return FCL_ecdsa.ecdsa_verify(messageHash, webAuthnAuth.r, webAuthnAuth.s, x, y);
    }

    /// @dev RIP-7212 precompile call. Writes output to scratch space to distinguish
    ///      empty returns from zero words. Returns true if signature is valid.
    function _rip7212(bytes32 h, uint256 r, uint256 s, uint256 qx, uint256 qy) private view returns (bool isValid) {
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, h)
            mstore(add(ptr, 0x20), r)
            mstore(add(ptr, 0x40), s)
            mstore(add(ptr, 0x60), qx)
            mstore(add(ptr, 0x80), qy)

            // Zero scratch space. If the precompile returns nothing, it will remain zero.
            mstore(0x00, 0)

            // Call RIP-7212 precompile (address 0x100). Return data (32 bytes) is written to 0x00.
            // staticcall returns success even if address has no code; output length may be zero.
            // We do not branch on the success flag; instead we read the scratch word.
            pop(staticcall(gas(), 0x100, ptr, 0xa0, 0x00, 0x20))

            isValid := mload(0x00)
        }
    }
}
