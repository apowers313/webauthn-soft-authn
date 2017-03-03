var assert = chai.assert;
var h = fido2Helpers;

var rpIdHash = h.hexToArrayBuffer("49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d9763"); // localhost


/***********************
 * Helpers
 ************************/


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
	it("window.webauthn exists", function() {
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

describe.only("authenticatorMakeCredential", function() {
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
		console.log ("h.clientDataHash", h.clientDataHash);
		return authnrUnderTest.authenticatorMakeCredential(h.rpIdHash, h.userAccountInformation, h.clientDataHash, h.scopedCredentialType)
			.then((scopedCredInfo) => {
				console.log (scopedCredInfo);
				assert.isObject (scopedCredInfo, scopedCredInfo);
				assert.isObject (scopedCredInfo.credential);
				assert.isString (scopedCredInfo.credential.type);
				assert.instanceOf (scopedCredInfo.credential.id, ArrayBuffer);
				assert.isObject (scopedCredInfo.attestation);
				assert.isString (scopedCredInfo.attestation.format);
				// assert.instanceOf (scopedCredInfo.attestation.clientData, ArrayBuffer);
				assert.instanceOf (scopedCredInfo.attestation.authenticatorData, ArrayBuffer);
				assert.instanceOf (scopedCredInfo.attestation.attestation, ArrayBuffer);
				console.log ("DONE!!?!");
			});
	});
});

describe("authenticatorGetAssertion", function() {

});

describe("authenticatorCancel", function() {

});

describe.skip("self attestation", function() {
	function verifyCbor(cbor, offset) {
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

	function verifyAttestationData(ad, offset) {
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
		verifyCbor(ad, offset + 50);
	}

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
			verifyCbor(cbor, 0);
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
				verifyAttestationData(ad, 0);
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
				verifyAttestationData(ad, 37);
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