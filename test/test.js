var assert = chai.assert;

/***********************
 * Helpers
 ************************/
var userAccountInformation = {
	rpDisplayName: "PayPal",
	displayName: "John P. Smith",
	name: "johnpsmith@gmail.com",
	id: "1098237235409872",
	imageUri: "https://pics.paypal.com/00/p/aBjjjpqPb.png"
};
var cryptoParams = [{
	type: "ScopedCred",
	algorithm: "RSASSA-PKCS1-v1_5",
}];
var expectedCryptoParams = {
	type: "ScopedCred",
	algorithm: "RSASSA-PKCS1-v1_5",
};
var challenge = "Y2xpbWIgYSBtb3VudGFpbg";
// var timeoutSeconds = 300; // 5 minutes
var timeoutSeconds = 1;
var blacklist = []; // No blacklist
var extensions = {
	"fido.location": true // Include location information in attestation
};
var calculatedClientData = {
	challenge: "Y2xpbWIgYSBtb3VudGFpbg",
	facet: "http://localhost:8000",
	hashAlg: "S256"
};
var expectedClientDataHash = new ArrayBuffer([227, 176, 196, 66, 152, 252, 28, 20, 154, 251, 244, 200, 153, 111, 185, 36, 39, 174, 65, 228, 100, 155, 147, 76, 164, 149, 153, 27, 120, 82, 184, 85]);
var validMakeCredential = {
	credential: {
		type: 'ScopedCred',
		id: '8DD7414D-EE43-474C-A05D-FDDB828B663B'
	},
	publicKey: {
		kty: 'RSA',
		alg: 'RS256',
		ext: false,
		n: 'lMR4XoxRiY5kptgHhh1XLKnezHC2EWPIImlHS-iUMSKVH32WWUKfEoY5Al_exPtcVuUfcNGtMoysAN65PZzcMKXaQ-2a8AebKwe8qQGBc4yY0EkP99Sgb80rAf1S7s-JRNVtNTRb4qrXVCMxZHu3ubjsdeybMI-fFKzYg9IV6DPotJyx1OpNSdibSwWKDTc5YzGfoOG3vA-1ae9oFOh5ZolhHnr5UkodFKUaxOOHfPrAB0MVT5Y5Stvo_Z_1qFDOLyOWdhxxzl2at3K9tyQC8kgJCNKYsq7-EFzvA9Q90PC6SxGATQoICKn2vCNMBqVHLlTydBmP7-8MoMxefM277w',
		e: 'AQAB'
	},
	attestation: null
};

describe("Prerequisites (if these fail, so will everything else)", function() {
	it("window.webauthn exists", function() {
		assert.isDefined(window.webauthn, "window.webauthn should be defined");
	});

	it("makeCredential exists", function() {
		assert.isDefined(window.webauthn.makeCredential, "makeCredential should exist on WebAuthn object");
		assert.isFunction(window.webauthn.makeCredential, "makeCredential should be a function");
	});

	it("getAssertion exists", function() {
		assert.isDefined(window.webauthn.getAssertion, "getAssertion should exist on WebAuthn object");
		assert.isFunction(window.webauthn.getAssertion, "getAssertion should be a function");
	});

	it("addAuthenticator exists", function() {
		assert.isDefined(window.webauthn.addAuthenticator, "addAuthenticator should exist on WebAuthn object");
		assert.isFunction(window.webauthn.addAuthenticator, "addAuthenticator should be a function");
	});

	it("listAuthenticators exists and has length greater than 0", function() {
		assert.isDefined(window.webauthn.listAuthenticators, "addAuthenticator should exist on WebAuthn object");
		assert.isFunction(window.webauthn.listAuthenticators, "addAuthenticator should be a function");
		var authnList = window.webauthn.listAuthenticators();
		console.log("Authn List:", authnList);
		assert(authnList.length > 0);
	});

});

describe("Basic tests", function() {
	it("does makeCredential", function() {
		var webAuthnAPI = window.webauthn;

		// auth.authenticatorMakeCredential = authenticatorMakeCredential;
		// var spy = sinon.spy(auth, "authenticatorMakeCredential");
		// webAuthnAPI.addAuthenticator(auth);

		return webAuthnAPI.makeCredential(userAccountInformation, cryptoParams, challenge,
				timeoutSeconds, blacklist, extensions)
			.then(function(ret) {
				// sinon.assert.calledOnce(spy);
				// assert.deepEqual(ret, ["beer"], "authenticatorMakeCredential should give me ['beer']");
				assert.isDefined(ret.credential, "Should return credential");
				assert.isDefined(ret.attestation, "Should return attestation");
				assert.isDefined(ret.publicKey, "Should return publicKey");
			});
	});

	it.only("does getAssertion", function() {
		var webAuthnAPI = window.webauthn;

		// auth.authenticatorMakeCredential = authenticatorMakeCredential;
		// var spy = sinon.spy(auth, "authenticatorMakeCredential");
		// webAuthnAPI.addAuthenticator(auth);

		return webAuthnAPI.makeCredential(userAccountInformation, cryptoParams, challenge,
				timeoutSeconds, blacklist, extensions)
			.then(function(ret) {
				// sinon.assert.calledOnce(spy);
				// assert.deepEqual(ret, ["beer"], "authenticatorMakeCredential should give me ['beer']");
				assert.isDefined(ret.credential, "Should return credential");
				assert.isDefined(ret.attestation, "Should return attestation");
				assert.isDefined(ret.publicKey, "Should return publicKey");
				return webAuthnAPI.getAssertion();
			})
			.then(function() {
				// done();
				// assert (false, "Should not pass");
				return true;
			})
			.catch(function(ret) {
				assert (false, "Should not fail");
				// done();
			});
	});
});