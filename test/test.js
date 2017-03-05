var assert = chai.assert;
var h = fido2Helpers;

/***********************
 * Helpers
 ************************/
function verifyAuthenticatorData(ad, baseOffset, rpIdHash, attestation, extensions) {
	// make sure the length of the signature is sane
	// console.log ("attestation", attestation);
	// console.log ("extensions", extensions);
	if (!attestation && !extensions) {
		assert.strictEqual(ad.byteLength - baseOffset, 37);
	} else {
		assert.isAbove(ad.byteLength - baseOffset, 37);
	}

	// check RP ID hash
	var offset = baseOffset;
	ad = new Uint8Array(ad);
	rpIdHash = new Uint8Array(rpIdHash);
	assert.strictEqual(rpIdHash.byteLength, 32);
	for (let i = 0; i < rpIdHash.byteLength; i++) {
		assert.strictEqual(ad[offset + i], rpIdHash[i]);
	}
	offset += rpIdHash.byteLength;

	// don't check counter

	// check flags
	if (attestation && extensions) {
		assert.strictEqual(ad[offset], 0xC1);
	} else if (attestation) {
		assert.strictEqual(ad[offset], 0x41);
	} else if (extensions) {
		assert.strictEqual(ad[offset], 0x81);
	} else {
		assert.strictEqual(ad[offset], 0x01);
	}

	if (attestation) {
		verifyAttestationStatement(ad, baseOffset + 37);
	}
}

function verifyRsaSig(sig) {
	assert.strictEqual(sig.byteLength, 256);
};

function verifyRsaCred(cbor, offset) {
	if (cbor instanceof ArrayBuffer) {
		cbor = new Uint8Array(cbor);
	}
	// XXX: yes, I realize that I could just compare against buffers
	// I'm doing this more verbose format to assist in identifying which
	// byte is wrong, because I'm pretty sure these formats are going
	// to be changing and I'm going to be debugging these later
	assert.strictEqual(cbor[offset + 0], 0xA3); // map, length 3
	assert.strictEqual(cbor[offset + 1], 0x63); // key, length 3
	assert.strictEqual(cbor[offset + 2], 0x61); // "a"
	assert.strictEqual(cbor[offset + 3], 0x6C); // "l"
	assert.strictEqual(cbor[offset + 4], 0x67); // "g"
	assert.strictEqual(cbor[offset + 5], 0x65); // key, length 5
	assert.strictEqual(cbor[offset + 6], 0x52); // "R"
	assert.strictEqual(cbor[offset + 7], 0x53); // "S"
	assert.strictEqual(cbor[offset + 8], 0x32); // "2"
	assert.strictEqual(cbor[offset + 9], 0x35); // "5"
	assert.strictEqual(cbor[offset + 10], 0x36); // "6"
	assert.strictEqual(cbor[offset + 11], 0x61); // key, length 1
	assert.strictEqual(cbor[offset + 12], 0x6e); // "n"
	assert.strictEqual(cbor[offset + 13], 0x59); // big byte string
	assert.strictEqual(cbor[offset + 14], 0x01); // length 256 (msb)
	assert.strictEqual(cbor[offset + 15], 0x00); // length 256 (lsb)
	// 256 bytes of random public key
	assert.strictEqual(cbor[offset + 272], 0x61); // key, length 1
	assert.strictEqual(cbor[offset + 273], 0x65); // "e"
	assert.strictEqual(cbor[offset + 274], 0x43); // byte string
	assert.strictEqual(cbor[offset + 275], 0x01); // 65537
	assert.strictEqual(cbor[offset + 276], 0x00);
	assert.strictEqual(cbor[offset + 277], 0x01);
}

function verifyAttestationStatement(ad, offset) {
	if (ad instanceof ArrayBuffer) {
		ad = new Uint8Array(ad);
	}
	assert.strictEqual(ad[offset + 0], 0xF1); // AAID[0]
	assert.strictEqual(ad[offset + 1], 0xD0); // AAID[1]
	assert.strictEqual(ad[offset + 2], 0xF1); // AAID[2]
	assert.strictEqual(ad[offset + 3], 0xD0); // AAID[3]
	assert.strictEqual(ad[offset + 4], 0xF1); // AAID[4]
	assert.strictEqual(ad[offset + 5], 0xD0); // AAID[5]
	assert.strictEqual(ad[offset + 6], 0xF1); // AAID[6]
	assert.strictEqual(ad[offset + 7], 0xD0); // AAID[7]
	assert.strictEqual(ad[offset + 8], 0xF1); // AAID[8]
	assert.strictEqual(ad[offset + 9], 0xD0); // AAID[9]
	assert.strictEqual(ad[offset + 10], 0xF1); // AAID[10]
	assert.strictEqual(ad[offset + 11], 0xD0); // AAID[11]
	assert.strictEqual(ad[offset + 12], 0xF1); // AAID[12]
	assert.strictEqual(ad[offset + 13], 0xD0); // AAID[13]
	assert.strictEqual(ad[offset + 14], 0xF1); // AAID[14]
	assert.strictEqual(ad[offset + 15], 0xD0); // AAID[15]
	assert.strictEqual(ad[offset + 16], 0x00); // cred length (msb)
	assert.strictEqual(ad[offset + 17], 0x20); // cred length (lsb) = 32
	verifyRsaCred(ad, offset + 50);
}

function verifyPackedAttestationCbor(cbor, offset) {
	if (cbor instanceof ArrayBuffer) {
		cbor = new Uint8Array(cbor);
	}
	assert.strictEqual(cbor[offset + 0], 0xA3); // map(3)
	assert.strictEqual(cbor[offset + 1], 0x63); // key(3)
	assert.strictEqual(cbor[offset + 2], 0x66); // "f"
	assert.strictEqual(cbor[offset + 3], 0x6D); // "m"
	assert.strictEqual(cbor[offset + 4], 0x74); // "t"
	assert.strictEqual(cbor[offset + 5], 0x66); // text(6)
	assert.strictEqual(cbor[offset + 6], 0x70); // "p"
	assert.strictEqual(cbor[offset + 7], 0x61); // "a"
	assert.strictEqual(cbor[offset + 8], 0x63); // "c"
	assert.strictEqual(cbor[offset + 9], 0x6B); // "k"
	assert.strictEqual(cbor[offset + 10], 0x65); // "e"
	assert.strictEqual(cbor[offset + 11], 0x64); // "d"
	assert.strictEqual(cbor[offset + 12], 0x68); // key(8)
	assert.strictEqual(cbor[offset + 13], 0x61); // "a"
	assert.strictEqual(cbor[offset + 14], 0x75); // "u"
	assert.strictEqual(cbor[offset + 15], 0x74); // "t"
	assert.strictEqual(cbor[offset + 16], 0x68); // "h"
	assert.strictEqual(cbor[offset + 17], 0x44); // "D"
	assert.strictEqual(cbor[offset + 18], 0x61); // "a"
	assert.strictEqual(cbor[offset + 19], 0x74); // "t"
	assert.strictEqual(cbor[offset + 20], 0x61); // "a"
	assert.strictEqual(cbor[offset + 21], 0x59); // bytes(365)
	assert.strictEqual(cbor[offset + 22], 0x01); // ...
	assert.strictEqual(cbor[offset + 23], 0x6D); // ...
	verifyAuthenticatorData (cbor, 24, h.rpIdHash, true, false);

	// A3 63 66 6D 74 66 70 61 63 6B 65 64 68 61 75 74
	// 68 44 61 74 61 59 01 6D 49 96 0D E5 88 0E 8C 68
	// 74 34 17 0F 64 76 60 5B 8F E4 AE B9 A2 86 32 C7
	// 99 5C F3 BA 83 1D 97 63 41 00 00 00 01 F1 D0 F1
	// D0 F1 D0 F1 D0 F1 D0 F1 D0 F1 D0 F1 D0 00 20 6E
	// B7 1A A3 6D 08 30 4E CB 1E 0B 08 87 0B 56 D4 F8
	// E8 52 E4 EF 93 2E 7B 4F 53 9B 53 3C 19 57 CC A3
	// 63 61 6C 67 65 52 53 32 35 36 61 6E 59 01 00 E5
	// 89 D3 03 B6 21 25 C8 4D 69 5A EE 22 91 3A 63 24
	// 42 4E CF 50 7E 52 20 DE 88 9B 5A 64 14 12 E3 B1
	// CB F6 23 D5 A5 6A 0C 49 BA CE BB BB 0A 5A 0D A8
	// C5 C5 C3 68 A7 2F 5F E3 C4 13 62 C9 75 DE 0B 3F
	// 9E 1F 64 84 0E D8 0E 44 89 31 48 86 62 B9 C5 07
	// F8 DD 09 0C 34 8F 59 F7 45 CF 8F 3B 05 F3 14 84
	// 45 8B 7B 33 31 99 A0 1D F4 8B 21 F4 C5 6C AC A9
	// F0 63 1E CF A9 BA 8A 9A 6A D9 69 F1 CD 37 62 62
	// D2 58 B2 F2 94 E1 D2 C1 D0 2E B0 5B F4 1E 0A FA
	// 27 A2 B1 DD AB 15 14 8A AC B6 85 83 70 AF 2C 29
	// E7 F7 21 EE 12 DE 5B 41 F9 FB C4 7F 41 4C 31 EC
	// A9 AB D4 3A 0C 61 0D B1 2F 75 44 01 07 64 66 EC
	// 15 C5 1D 7B 7F E9 9E 5F 8A 37 5D 42 8C 68 A9 E2
	// F0 E5 E7 A4 C4 E2 EA 58 95 27 E5 FF 3D A0 F7 E8
	// 07 A9 44 CB 13 C3 C3 16 0A A1 2E 96 DD 22 F3 63
	// E3 1A 24 1D 1B 92 B4 AB 9C A2 23 C6 F3 0A A9 61
	// 65 43 01 00 01 67 61 74 74 53 74 6D 74 A2 63 61
	// 6C 67 65 52 53 32 35 36 63 73 69 67 59 01 00 2F
	// B9 6F A4 D2 82 FE 22 9A 98 14 81 4F B1 34 5E 08
	// 59 BE 72 48 0D AB 26 3E 64 66 F0 16 F4 02 FA 64
	// DC 34 CF BE 67 03 FF 30 A3 34 96 22 D5 5E BF 07
	// F4 CE E3 E3 E6 4A 5E 26 9D 84 91 99 75 7F 48 E5
	// B3 D3 AF 28 19 A7 4A 16 44 94 49 BB A4 DD DF 9E
	// FE E1 24 FD 8C C7 72 64 89 ED 96 79 F4 F4 20 DF
	// 85 5A 14 EE E1 CA AA 4E 35 26 51 EC 38 C4 6E F9
	// 26 10 21 F3 66 87 16 95 AB CF 30 6E F0 A1 F8 37
	// 1C 2B 20 DB AC 7D D4 55 02 2C 0D 03 3F 39 B1 FA
	// 65 02 63 6C 0B 10 B3 ED 80 2F 37 9D 15 8C E9 2E
	// C7 E1 05 73 83 C5 DF B4 8A 4A 38 E1 34 B9 CE 26
	// 14 CF 63 32 40 AE 3F 72 E4 31 D3 29 55 1F B1 6C
	// D6 DB 11 75 AF 39 BA FA 80 9E 1E 41 90 7B 7A CC
	// 52 47 2B 51 BB B8 AD 48 5B BD 83 F1 60 F0 17 8C
	// 95 E9 1F 87 7C 69 9C AE 54 95 01 32 91 9B 60 08
	// BE 69 F8 CB 0B E2 8B E0 4C 6D 28 01 9B 05 38
}

// var challenge = "Y2xpbWIgYSBtb3VudGFpbg";
// // var timeoutSeconds = 300; // 5 minutes
// var timeoutSeconds = 1;
// var blacklist = []; // No blacklist
// var extensions = {
// 	"fido.location": true // Include location information in attestation
// };
// var calculatedClientData = {
// 	challenge: "Y2xpbWIgYSBtb3VudGFpbg",
// 	facet: "http://localhost:8000",
// 	hashAlg: "S256"
// };
// var expectedClientDataHash = new ArrayBuffer([227, 176, 196, 66, 152, 252, 28, 20, 154, 251, 244, 200, 153, 111, 185, 36, 39, 174, 65, 228, 100, 155, 147, 76, 164, 149, 153, 27, 120, 82, 184, 85]);
// var validMakeCredential = {
// 	credential: {
// 		type: 'ScopedCred',
// 		id: '8DD7414D-EE43-474C-A05D-FDDB828B663B'
// 	},
// 	publicKey: {
// 		kty: 'RSA',
// 		alg: 'RS256',
// 		ext: false,
// 		n: 'lMR4XoxRiY5kptgHhh1XLKnezHC2EWPIImlHS-iUMSKVH32WWUKfEoY5Al_exPtcVuUfcNGtMoysAN65PZzcMKXaQ-2a8AebKwe8qQGBc4yY0EkP99Sgb80rAf1S7s-JRNVtNTRb4qrXVCMxZHu3ubjsdeybMI-fFKzYg9IV6DPotJyx1OpNSdibSwWKDTc5YzGfoOG3vA-1ae9oFOh5ZolhHnr5UkodFKUaxOOHfPrAB0MVT5Y5Stvo_Z_1qFDOLyOWdhxxzl2at3K9tyQC8kgJCNKYsq7-EFzvA9Q90PC6SxGATQoICKn2vCNMBqVHLlTydBmP7-8MoMxefM277w',
// 		e: 'AQAB'
// 	},
// 	attestation: null
// };

describe("Prerequisites (if these fail, so will everything else)", function() {
	it("window.navigator.authentication exists", function() {
		assert.isDefined(window.navigator.authentication, "window.navigator.authentication should be defined");
	});

	it("makeCredential exists", function() {
		assert.isDefined(window.navigator.authentication.makeCredential, "makeCredential should exist on WebAuthn object");
		assert.isFunction(window.navigator.authentication.makeCredential, "makeCredential should be a function");
	});

	it("getAssertion exists", function() {
		assert.isDefined(window.navigator.authentication.getAssertion, "getAssertion should exist on WebAuthn object");
		assert.isFunction(window.navigator.authentication.getAssertion, "getAssertion should be a function");
	});

	it("addAuthenticator exists", function() {
		assert.isDefined(window.navigator.authentication.addAuthenticator, "addAuthenticator should exist on WebAuthn object");
		assert.isFunction(window.navigator.authentication.addAuthenticator, "addAuthenticator should be a function");
	});

	it("listAuthenticators exists and has length greater than 0", function() {
		assert.isDefined(window.navigator.authentication.listAuthenticators, "addAuthenticator should exist on WebAuthn object");
		assert.isFunction(window.navigator.authentication.listAuthenticators, "addAuthenticator should be a function");
		var authnList = window.navigator.authentication.listAuthenticators();
		console.log("Authn List:", authnList);
		assert(authnList.length > 0);
	});

	it("proxies addAuthenticator", function() {
		assert.instanceOf(authnrUnderTest, navigator.authentication.fidoAuthenticator);
	});
});

// these tests require the polyfill to be loaded, so they are being deprecated
describe.skip("Basic tests", function() {
	this.slow(1000);
	it("does makeCredential", function() {
		var webAuthnAPI = window.navigator.authentication;

		// auth.authenticatorMakeCredential = authenticatorMakeCredential;
		// var spy = sinon.spy(auth, "authenticatorMakeCredential");
		// webAuthnAPI.addAuthenticator(auth);

		return webAuthnAPI.makeCredential(h.userAccountInformation, h.cryptoParams, h.challenge, h.opts)
			.then(function(ret) {
				// sinon.assert.calledOnce(spy);
				// assert.deepEqual(ret, ["beer"], "authenticatorMakeCredential should give me ['beer']");
				assert.isDefined(ret.credential, "Should return credential");
				assert.isDefined(ret.attestation, "Should return attestation");
				assert.isDefined(ret.publicKey, "Should return publicKey");
			});
	});

	it("does getAssertion", function() {
		var webAuthnAPI = window.navigator.authentication;

		// auth.authenticatorMakeCredential = authenticatorMakeCredential;
		// var spy = sinon.spy(auth, "authenticatorMakeCredential");
		// webAuthnAPI.addAuthenticator(auth);

		return webAuthnAPI.makeCredential(h.userAccountInformation, h.cryptoParams, h.challenge, h.opts)
			.then(function(ret) {
				// sinon.assert.calledOnce(spy);
				// assert.deepEqual(ret, ["beer"], "authenticatorMakeCredential should give me ['beer']");
				assert.isDefined(ret.credential, "Should return credential");
				assert.isDefined(ret.attestation, "Should return attestation");
				assert.isDefined(ret.publicKey, "Should return publicKey");
				return webAuthnAPI.getAssertion();
				// })
				// .then((assertion) => {
				// 	assert.isObject (assertion);
				// 	assert.isObject (assertion.credential);
				// 	assert.instanceOf (assertion.clientData, ArrayBuffer);
				// 	assert.instanceOf (assertion.authenticatorData, ArrayBuffer);
				// 	assert.instanceOf (assertion.signature, ArrayBuffer);
			});
	});
	it("can make and then assert a credential");
	it("can make two credentials");
	it("can assert the same credential multiple times");
});

describe("authenticatorMakeCredential", function() {
	it("throws when called with no arguments", function(done) {
		authnrUnderTest.authenticatorMakeCredential()
			.then(() => {
				assert.fail("authenticatorMakeCredential with no args should throw TypeError");
			})
			.catch((err) => {
				assert.instanceOf(err, TypeError);
				done();
			});
	});

	it("returns a credential", function() {
		console.log("h.clientDataHash", h.clientDataHash);
		return authnrUnderTest.authenticatorMakeCredential(h.rpIdHash, h.userAccountInformation, h.clientDataHash, h.scopedCredentialType)
			.then((scopedCredInfo) => {
				console.log(scopedCredInfo);
				assert.isObject(scopedCredInfo, scopedCredInfo);
				assert.isObject(scopedCredInfo.credential);
				assert.strictEqual(scopedCredInfo.credential.type, "ScopedCred");
				assert.instanceOf(scopedCredInfo.credential.id, ArrayBuffer);
				assert.isObject(scopedCredInfo.attestation);
				assert.isString(scopedCredInfo.attestation.format);
				// assert.instanceOf (scopedCredInfo.attestation.clientData, ArrayBuffer);
				assert.instanceOf(scopedCredInfo.attestation.authenticatorData, ArrayBuffer);
				assert.instanceOf(scopedCredInfo.attestation.attestation, ArrayBuffer);
				verifyAuthenticatorData (scopedCredInfo.attestation.authenticatorData, 0, h.rpIdHash, true, false);
				verifyPackedAttestationCbor (scopedCredInfo.attestation.attestation, 0);
				// TODO:
				// 		verifyRsaCred
				// 		verifyAuthenticatorData
				// 		verifyAttestationStatement
			});
	});
});

describe("authenticatorGetAssertion", function() {
	it("returns an attestation", function() {
		return authnrUnderTest.authenticatorMakeCredential(h.rpIdHash, h.userAccountInformation, h.clientDataHash, h.scopedCredentialType)
			.then(() => {
				return authnrUnderTest.authenticatorGetAssertion(h.rpIdHash, h.clientDataHash);
			})
			.then((webAuthnAssertion) => {
				console.log("Got assertion", webAuthnAssertion);
				assert.isObject(webAuthnAssertion);
				// printHex("credentialId", webAuthnAssertion.credentialId);
				// printHex("authenticatorData", webAuthnAssertion.authenticatorData);
				// printHex("sig", webAuthnAssertion.signature);
				assert.isObject(webAuthnAssertion.credential);
				assert.strictEqual(webAuthnAssertion.credential.type, "ScopedCred");
				assert.instanceOf(webAuthnAssertion.credential.id, ArrayBuffer);
				assert.strictEqual(webAuthnAssertion.credential.id.byteLength, 32);
				assert.instanceOf(webAuthnAssertion.authenticatorData, ArrayBuffer);
				assert.instanceOf(webAuthnAssertion.signature, ArrayBuffer);
				verifyAuthenticatorData(webAuthnAssertion.authenticatorData, 0, h.rpIdHash, false, false);
				verifyRsaSig(webAuthnAssertion.signature);
			});
	});
});

describe("authenticatorCancel", function() {

});

// TODO: this really doesn't belong here...
describe("integration testing", function() {
	it("makeCredential returns a valid credential", function() {
		var webAuthnAPI = window.navigator.authentication;

		return webAuthnAPI.makeCredential(h.userAccountInformation, h.cryptoParams, h.challenge)
			.then((scopedCredInfo) => {
				assert.isObject(scopedCredInfo);
				assert.isObject(scopedCredInfo.credential);
				assert.strictEqual(scopedCredInfo.credential.type, "ScopedCred");
				assert.instanceOf(scopedCredInfo.credential.id, ArrayBuffer);
				assert.isObject(scopedCredInfo.attestation);
				assert.isString(scopedCredInfo.attestation.format);
				// assert.instanceOf (scopedCredInfo.attestation.clientData, ArrayBuffer);
				assert.instanceOf(scopedCredInfo.attestation.authenticatorData, ArrayBuffer);
				assert.instanceOf(scopedCredInfo.attestation.attestation, ArrayBuffer);
				assert.instanceOf(scopedCredInfo.clientData, ArrayBuffer);
				verifyAuthenticatorData (scopedCredInfo.attestation.authenticatorData, 0, h.rpIdHash, true, false);
				verifyPackedAttestationCbor (scopedCredInfo.attestation.attestation, 0);
				assert(h.arrayBufferEquals(scopedCredInfo.clientData, h.clientDataJsonBuf, "clientData ArrayBuffer doesn't match"));
				// console.log ("FINAL");
				// console.log ("scopedCredInfo", scopedCredInfo);
				// printHex ("scopedCredInfo.credential.id", scopedCredInfo.credential.id);
				// printHex ("scopedCredInfo.attestation.authenticatorData", scopedCredInfo.attestation.authenticatorData);
			});
	});

	it.only("getAssertion returns a valid assertion", function() {
		var webAuthnAPI = window.navigator.authentication;

		return webAuthnAPI.makeCredential(h.userAccountInformation, h.cryptoParams, h.challenge)
		.then(() => {
			return webAuthnAPI.getAssertion(h.challenge);
		})
		.then((webAuthnAssertion) => {
			console.log("webAuthnAssertion", webAuthnAssertion);
			assert.isObject (webAuthnAssertion);
			assert.isObject (webAuthnAssertion.credential);
			assert.instanceOf (webAuthnAssertion.credential.id, ArrayBuffer);
			assert.strictEqual (webAuthnAssertion.credential.type, "ScopedCred");
			assert.instanceOf (webAuthnAssertion.clientData, ArrayBuffer);
			assert.instanceOf (webAuthnAssertion.authenticatorData, ArrayBuffer);
			assert.instanceOf (webAuthnAssertion.signature, ArrayBuffer);
			verifyAuthenticatorData (webAuthnAssertion.authenticatorData, 0, h.rpIdHash, false, false);
			assert(h.arrayBufferEquals(webAuthnAssertion.clientData, h.clientDataJsonBuf, "clientData ArrayBuffer doesn't match"));
			console.log ("FINAL");
		});
	});
});

// TODO: at one point in time these functions were all outside the IIFE...
// now it's really hard to test them
describe.skip("self attestation", function() {

	it("create a credential ID", function() {
		var buf = createCredentialId(32);
		assert.instanceOf(buf, ArrayBuffer);
		assert.strictEqual(buf.byteLength, 32);
	});

	it("creates a RSA256 credential", function() {
		var p = createCredential();
		assert.instanceOf(p, Promise);
		return p.then((ret) => {
			assert.instanceOf(ret.n, ArrayBuffer);
			assert.instanceOf(ret.e, ArrayBuffer);
			assert.isObject(ret.jwk);
			assert.isObject(ret.keyPair);
			assert.instanceOf(ret.id, ArrayBuffer);
			assert.isNumber(ret.idLen);
			assert.strictEqual(ret.idLen, 32);
			assert.instanceOf(ret.cbor, ArrayBuffer);
			assert.isNumber(ret.cborLen);
			assert.strictEqual(ret.cborLen, 278);

			// verify RS256 CBOR credential
			var cbor = new Uint8Array(ret.cbor);
			verifyRsaCred(cbor, 0);
		});
	});

	it("creates attestation data", function() {
		return createCredential()
			.then((credObj) => {
				var attestDataBuf = createAttestationData(credObj);
				assert.instanceOf(attestDataBuf, ArrayBuffer);
				assert.strictEqual(attestDataBuf.byteLength, 328);

				// verify attestation data
				var ad = new Uint8Array(attestDataBuf);
				verifyAttestationStatement(ad, 0);
			});
	});

	it("creates authenticator data w/ attestation", function() {
		return createCredential()
			.then((credObj) => {
				var opts = {
					attestation: true,
					extensions: false
				};
				var p = createAuthenticatorData(rpIdHash, credObj, opts);
				assert.instanceOf(p, Promise);
				return p;
			})
			.then((authnrData) => {
				assert.instanceOf(authnrData, ArrayBuffer);

				// validate authenticator data
				// RPID
				var ad = new Uint8Array(authnrData);
				var rpid = new Uint8Array(rpIdHash);
				assert.strictEqual(rpIdHash.byteLength, 32);
				for (let i = 0; i < rpIdHash.byteLength; i++) {
					assert.strictEqual(ad[i], rpid[i]);
				}
				console.log(ad[32].toString(16));
				// flags
				assert.strictEqual(ad[32], 0x41);
				// counter
				assert.strictEqual(ad[33], 0);
				assert.strictEqual(ad[34], 0);
				assert.strictEqual(ad[35], 0);
				assert.strictEqual(ad[36], 1);
				// attestation data
				verifyAttestationStatement(ad, 37);
			});
	});

	it("creates a signature", function() {
		var credObj;

		return createCredential()
			.then((co) => {
				credObj = co;
				var opts = {
					attestation: true,
					extensions: false
				};
				var p = createAuthenticatorData(rpIdHash, credObj, opts);
				assert.instanceOf(p, Promise);
				return p;
			})
			.then((authnrData) => {
				var p = createSignature(credObj.keyPair, authnrData, h.clientDataHash);
				assert.instanceOf(p, Promise);
				return p;
			});
	});

	it("creates a packed attestation", function() {
		return createCredential()
			.then((credObj) => {
				var p = createPackedAttestation(rpIdHash, h.clientDataHash, credObj);
				assert.instanceOf(p, Promise);
				return p;
			})
			.then((packedAttestation) => {
				console.log(packedAttestation);
				printHex("packed attestation", packedAttestation);
				return packedAttestation;
			});
	});
	it("creates a packed self-attestation statement");
});

/* JSHINT */
/* globals authnrUnderTest */