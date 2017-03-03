// IIFE for clean namespace
(function() {

    if (navigator.authentication === undefined) {
        console.log("WebAuthn API not found, can't load authenticator.");
        return;
    }

    if (navigator.authentication.fidoAuthenticator === undefined ||
        navigator.authentication.addAuthenticator === undefined) {
        console.log("Unsupported version of WebAuthn API in use, can't load authenticator");
        return;
    }

    class softAuthn extends navigator.authentication.fidoAuthenticator {
        constructor(opt) {
            super(opt);

            if (window.crypto.subtle === undefined) {
                throw new Error("Creating authenticator: window.crypto.subtle not found");
            }

            if (window.indexedDB === undefined) {
                throw new Error("Creating authenticator: window.indexedDB not found");
            }

            // TODO: manage / verify options
            // -- crypto params
            // -- authn type (PIN, pop-up, none, etc.)
            // -- attestation type
            this.name = "softAuthenticator";
            this.preferredCrypto = "RSASSA-PKCS1-v1_5";
            this.cryptoBits = 2048;
            this.dbName = "scoped-cred-store";
            this.dbTableName = "creds";
            this.debug = 0;
            this.confirmType = "none"; // TODO: shouldn't be on the object

            // TODO: debug should be private and static to strip out some of these options in minified code?
            if (this.debug) {
                console.log("IN DEBUG MODE");
                this.confirmType = "none";
                console.log("Deleting db:", this.dbName);
                // _dbDelete.call(this);
                var f = _dbDelete.bind(this);
                f();
            }
        }

        // TODO: credentialType arg (ScopedCred)
        // TODO: list of Credentials arg, that are already known so that new creds. aren't needlessly created
        // TODO: attestationChallenge arg
        authenticatorMakeCredential(rpIdHash, account, clientDataHash, scopedCredentialType, blacklist, extensions) {
            return new Promise((resolve, reject) => { // TODO: just reurn the inner promise
                console.log("!!! MAKE CREDENTIAL");
                console.log("RP ID Hash:", rpIdHash);
                console.log("account", account);
                console.log("clientDataHash", clientDataHash);
                console.log("scopedCredentialType:", scopedCredentialType);
                console.log("blacklist:", blacklist);
                console.log("extensions:", extensions);

                // TODO: verify arguments
                if (!(rpIdHash instanceof ArrayBuffer)) {
                    throw new TypeError("authenticatorMakeCredential expected rpIdHash to be ArrayBuffer");
                }

                console.log(account);
                if (typeof account !== "object" ||
                    typeof account.rpDisplayName !== "string" ||
                    typeof account.displayName !== "string" ||
                    typeof account.id !== "string") {
                    throw new TypeError("authenticatorMakeCredential expected 'account' to be object containing rpDisplayName, displayName, and id");
                }

                console.log("clientDataHash", clientDataHash);
                if (!(clientDataHash instanceof ArrayBuffer)) {
                    throw new TypeError("authenticatorMakeCredential expected clientDataHash to be ArrayBuffer");
                }

                if (typeof scopedCredentialType !== "string") {
                    throw new TypeError("authenticatorMakeCredential expected scopedCredentialType to be string");
                }

                // TODO: process extension data

                var credObj, webAuthnAttestation;

                // prompt for user permission
                return _userConfirmation.call(this, "Would you like to create an new account?", account.rpDisplayName, account.displayName)
                    .then((confirm) => {
                        // create a credential
                        return _createCredential();
                    })
                    .then((co) => {
                        // save credential object
                        credObj = co;
                        console.log("created credential:", credObj);
                        // create attestation
                        return _createPackedAttestation(rpIdHash, clientDataHash, credObj, {
                            attestation: true
                        });
                    })
                    .then((a) => {
                        // save attestation
                        webAuthnAttestation = a;
                        //     // create assymetric key pair and export public key
                        //     return window.crypto.subtle.generateKey({
                        //             // TODO: should be options for crypto, bits, hash, etc.
                        //             name: this.preferredCrypto,
                        //             modulusLength: this.cryptoBits, //can be 1024, 2048, or 4096
                        //             publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
                        //             hash: {
                        //                 name: "SHA-256" //can be "SHA-1", "SHA-256", "SHA-384", or "SHA-512"
                        //             },
                        //         },
                        //         false, ["sign", "verify"]
                        //     );
                        // })
                        // .then((keys) => {
                        //     // export public key
                        //     keyPair = keys;
                        //     return window.crypto.subtle.exportKey("jwk", keyPair.publicKey);
                        // })
                        // .then((jwkPk) => {
                        //     // dbInit
                        //     console.log("JWK Pk:", jwkPk);
                        //     publicKey = jwkPk;

                        return _dbInit.call(this);
                    })
                    .then(() => {
                        // store credential ID and RP ID for future use
                        return _dbCredCreate.call(this, account, rpIdHash, credObj);
                    })
                    // TODO: _dbClose()?
                    .then(() => {
                        var ret = {
                            credential: {
                                type: "ScopedCred",
                                id: credObj.id
                            },
                            attestation: webAuthnAttestation
                        };
                        // resolve with credential, publicKey, rawAttestation = { attestation.type, attestation.statement, attestation.clientData }
                        return resolve(ret);
                    });
            });
        }

        authenticatorGetAssertion(rpId, assertionChallenge, clientDataHash, whitelist, extensions) {
            return new Promise((resolve, reject) => {
                console.log("authenticatorGetAssertion");

                // verify arguments
                if (typeof rpId === "string") {
                    throw new TypeError("authenticatorGetAssertion expected rpId to be string");
                }

                if (!(assertionChallenge instanceof ArrayBuffer)) {
                    throw new TypeError("authenticatorGetAssertion expected assertionChallenge to be ArrayBuffer");
                }
                console.log("assertionChallenge", assertionChallenge);

                if (!(clientDataHash instanceof ArrayBuffer)) {
                    throw new TypeError("authenticatorGetAssertion expected clientDataHash to be ArrayBuffer");
                }

                // TODO: process whitelist
                // TODO: process extensions

                // lookup credentials by RP ID
                console.log("RP ID:", rpId);
                var selectedCred, authenticatorData;
                return _dbInit.call(this)
                    .then((db) => {
                        return _dbCredLookup(rpId);
                    })
                    .then((cred) => { // prompt for user permission
                        // TODO: filter found credentials by whitelist
                        // TODO: _userConfirmation should allow user to pick from an array of accounts
                        selectedCred = cred;
                        console.log("Using credential:", selectedCred);
                        return _userConfirmation.call(this, "Would you like to login to this account?", cred.rpName || "SERVICE MISSING", cred.userName || "USER MISSING");
                    })
                    .then((confirm) => { // create assertion
                        console.log("Creating assertion");
                        var SIG = {
                            TUP_FLAG: 0x01
                        };
                        var baseSignature = new DataView(new ArrayBuffer(5));
                        // set TUP flag in authenticator data
                        baseSignature.setUint8(0, SIG.TUP_FLAG);
                        // bump counter
                        baseSignature.setUint32(1, selectedCred.counter + 1);

                        // TODO: store counter
                        // TODO: create a single buffer with authenticatorData, clientDataHash and extensions

                        authenticatorData = baseSignature;
                        return baseSignature;
                    })
                    .then((authenticatorData) => { // sign assertion
                        console.log("Signing assertion");

                        var bufSz = authenticatorData.byteLength + clientDataHash.byteLength;
                        console.log("Creating buffer sized:", bufSz);
                        var sigBuffer = new Uint8Array(bufSz);
                        sigBuffer.set(new Uint8Array(authenticatorData), 0);
                        sigBuffer.set(new Uint8Array(clientDataHash), authenticatorData.byteLength);
                        sigBuffer = sigBuffer.buffer;

                        return window.crypto.subtle.sign({
                                name: this.preferredCrypto,
                            },
                            selectedCred.keyPair.privateKey, //from stored credential
                            sigBuffer //ArrayBuffer of data you want to sign
                        );
                    })
                    .then((signature) => { // resolve with credential, authenticatorData, signature
                        console.log("Signature length:", signature.byteLength);
                        var ret = {
                            credential: {
                                id: selectedCred.id,
                                type: "ScopedCred" // TODO: need to be more intelligent about this?
                            },
                            authenticatorData: authenticatorData.buffer,
                            signature: signature
                        };
                        console.log("All done", ret);
                        return resolve(ret);
                    })
                    .catch((err) => {
                        console.log("error in authenticatorGetAssertion:", err);
                        return reject(err);
                    });
            });
        }

        authenticatorCancel() {
            // not sure how to handle this... maybe throw? set flag and check above?
            return Promise.reject(new Error("Not Implemented"));
        }
    }

    // extend the authenticator object
    softAuthn.prototype = new navigator.authentication.fidoAuthenticator();

    function _dbDelete() {
        if (this.dbName === undefined) {
            throw new Error("Trying to delete undefined database");
        }

        var deleteRequest = window.indexedDB.deleteDatabase(this.dbName);

        deleteRequest.onerror = function(e) {
            console.log("Error deleting database");
        };

        deleteRequest.onsuccess = function(e) {
            console.log("Database successfully deleted:", this.dbName);
        }.bind(this);
    }

    // private variable for credential database
    var _credDb = null;

    function _dbInit() {
        if (_credDb) {
            return Promise.resolve(_credDb);
        }

        if (this.dbName === undefined) {
            console.log("dbName not found:", this.dbName);
            throw new Error("Trying to init database, but no name found");
        }

        return new Promise((resolve, reject) => {
            // create IndexedDatabase for storing Cred IDs / RPIDs?
            var request = indexedDB.open(this.dbName);

            request.onupgradeneeded = function() {
                console.log("Creating database...");
                var db = request.result;
                var store = db.createObjectStore("creds", {
                    keyPath: "id"
                });
                var idIdx = store.createIndex("by_rpIdHash", "rpIdHash", {
                    unique: false
                });
            };

            request.onsuccess = function() {
                console.log("Database created!");
                _credDb = request.result;
                return resolve(_credDb);
            };

            request.onerror = function() {
                return reject(new Error("Couldn't initialize DB"));
            };
        });
    }

    // TODO: lookup is supposed to be by RP ID ("example.com")
    //       but databases are stored by origin ("https://subdomain.example.com:443")
    //       so I'm not sure that this is going to work as expected if there
    //       are multiple ports or subdomains that the credentials are supposed to work with
    function _dbCredLookup(rpId) {
        return new Promise(function(resolve, reject) {
            var db = _credDb;
            var tx = db.transaction("creds", "readonly");

            var store = tx.objectStore("creds");
            var index = store.index("by_rpId", "rpId", {
                unique: false
            });
            console.log("rpId index unique:", index.unique);
            var request = index.get(rpId);
            request.onsuccess = function() {
                var matching = request.result;
                if (matching !== undefined) {
                    console.log("Found match:", matching);
                    return resolve(matching);
                } else {
                    console.log("No match found.");
                    return reject(new Error("Credential not found"));
                }
            };
        });
    }

    function _dbCredCreate(account, rpIdHash, credObj) {
        return new Promise((resolve, reject) => {
            var db = _credDb;
            var tx = db.transaction(this.dbTableName, "readwrite");
            var store = tx.objectStore(this.dbTableName);

            // TODO: create credential ID here

            var newCred = {
                rpName: account.rpDisplayName,
                userName: account.displayName,
                accountName: account.name,
                accountId: account.id,
                imageURL: account.imageURL,
                rpIdHash: rpIdHash,
                id: _buf2hex(credObj.id),
                idBuf: credObj.id,
                credCbor: credObj.cbor,
                credJwk: credObj.jwk,
                keyPair: credObj.keyPair,
                counter: 0
            };
            console.log("New Credential ID is:", _buf2hex(credObj.id));
            console.log("Saving New Credential:", newCred);
            store.put(newCred);

            tx.oncomplete = function() {
                return resolve(true);
            };

            tx.onerror = function(e) {
                console.log("ERROR");
                console.log(e);
                return reject(new Error("Couldn't create credential"));
            };
        });
    }

    function _generateCredId() {
        var newId = window.crypto.getRandomValues(new Uint8Array(16));
        var newHexId = "";
        for (let byte of newId) {
            newHexId += byte.toString(16);
        }
        console.log("New Credential ID:", newHexId);
        return newHexId;
    }

    function _generateAttestation() {
        return null;
    }

    function _userConfirmation(msg, rpDisplayName, displayName) {
        return new Promise((resolve, reject) => {
            console.log("Confirmation Type:", this.confirmType);
            switch (this.confirmType) {
                case "ok":
                    var result = confirm(msg + "\n" +
                        "Service: " + rpDisplayName + "\n" +
                        // "Website: " + rpId + "\n" +
                        "Account: " + displayName + "\n"
                    );
                    if (result === true) {
                        return resolve(true);
                    } else {
                        return reject(new Error("User declined confirmation"));
                    }
                    break;
                case "none":
                    return resolve(true);
                default:
                    return reject(new Error("Unknown User Confirmation Type:", this.confirmType));
            }

        });
    }
    /**
     * Creates a random credential ID
     * @param  {Number} len The length of the credential ID to create (default: 32)
     * @return {ArrayBuffer}     Credential ID as an ArrayBuffer
     * @private
     */
    function createCredentialId(len) {
        // TODO: length should be a parameter

        // default length is 32 bytes
        len = len || 32;
        var ret = new Uint8Array(len);
        window.crypto.getRandomValues(ret);
        return ret.buffer;
    }

    /**
     * Converts a credential object to a CBOR representation of the credential
     * @param  {String} alg     The JWK crypto algorithm for the credential. Currently only "RS256" is supported.
     * @param  {Object} credObj The credential object to be converted to CBOR
     * @return {ArrayBuffer}    The CBOR representation of the credential
     * @private
     */
    function credentialToCbor(alg, credObj) {
        switch (alg) {
            case "RS256":
                return CBOR.encode({
                    alg: alg,
                    n: new Uint8Array(credObj.n),
                    e: new Uint8Array(credObj.e)
                });
            default:
                throw new TypeError(`${alg} not supported in credentialToCbor()`);
        }
    }

    /**
     * Creates a key pair and returns them along with all the information needed for a credential
     * @return {Object} A Promise that resolves to a credential object with n, e, jwk, and keyPair attributes
     * @private
     */
    function _createCredential(opts) {
        // TODO:
        // opts
        //     idLen: length of credential (default: 32)
        //     cryptoType: type of credential (default: ECDSA)
        //     crytpoBits: number bits to be used for crypto keys (default: 256)
        var keyPair;
        var credId = createCredentialId();

        // generate a credential key pair
        return window.crypto.subtle.generateKey({
                // TODO: should be options for crypto, bits, hash, etc.
                name: "RSASSA-PKCS1-v1_5",
                modulusLength: 2048, //can be 1024, 2048, or 4096
                publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
                hash: {
                    name: "SHA-256" //can be "SHA-1", "SHA-256", "SHA-384", or "SHA-512"
                },
            },
            false, ["sign", "verify"]
        ).then((keys) => { // export public key
            keyPair = keys;
            return window.crypto.subtle.exportKey("jwk", keyPair.publicKey);
        }).then((jwkPk) => { // grab the right values from the JWK and return them
            var ret = {
                n: b64decode(jwkPk.n),
                e: b64decode(jwkPk.e),
                jwk: jwkPk,
                keyPair: keyPair,
                id: credId,
                idLen: credId.byteLength,
            };

            // convert the JWK to CBOR
            ret.cbor = credentialToCbor(jwkPk.alg, ret);
            ret.cborLen = ret.cbor.byteLength;

            console.log("cred obj:", ret);

            return ret;
        });
    }

    function createAttestationData(credObj, opts) {
        opts = opts || {};
        if (typeof credObj !== "object") {
            throw new TypeError("createAttestationData: expected credObj to be object");
        }

        // TODO: real AAGUID
        var myAaguid = [0xF1, 0xD0, 0xF1, 0xD0, 0xF1, 0xD0, 0xF1, 0xD0, 0xF1, 0xD0, 0xF1, 0xD0, 0xF1, 0xD0, 0xF1, 0xD0];

        // create a new dataview for the attestation
        var attestDataBuf = new ArrayBuffer(
            16 + // AAGUID
            2 + // Cred ID Len
            credObj.idLen + // Credential ID
            credObj.cborLen // Credential in CBOR Format
        );
        var attestData = new DataView(attestDataBuf);
        var offset = 0;

        // append AAGUID
        for (let i = 0; i < 16; i++) {
            attestData.setUint8(i, myAaguid[i]);
        }
        offset += 16;

        // set credential ID length
        attestData.setUint16(offset, credObj.idLen);
        offset += 2;

        // append credential ID
        var id = new Uint8Array(credObj.id);
        for (let i = 0; i < credObj.idLen; i++) {
            attestData.setUint8(i + offset, id[i]);
        }
        offset += credObj.idLen;

        // append credential in CBOR format
        var cbor = new Uint8Array(credObj.cbor);
        for (let i = 0; i < credObj.cborLen; i++) {
            attestData.setUint8(i + offset, cbor[i]);
        }

        return attestDataBuf;
    }

    function createAuthenticatorData(rpIdHash, credObj, opts) {
        opts = opts || {};
        var counter = 1; // TODO: manage counter

        var attData;

        return Promise.resolve(true) // get TUP -- TODO
            .then((tup) => { // get attestation data, if required
                if (tup !== true) {
                    throw new Error("TUP rejected");
                }

                if (opts.attestation) return createAttestationData(credObj);
                else return new ArrayBuffer(0);
            })
            .then((ad) => { // get extension data, if required
                attData = ad;
                if (opts.extensions) throw new Error("extensions not supported in createAuthenticatorData");
                else return new ArrayBuffer(0);
            })
            .then((extData) => { // create the authenticator data
                var hasAd = (attData.byteLength > 0);
                var hasEd = (extData.byteLength > 0);

                // create authenticator data
                var authnrDataBuf = new ArrayBuffer(
                    32 + // RPID Hash
                    1 + // Flags
                    4 + // Signature Counter
                    attData.byteLength + // attestation data
                    extData.byteLength // extensions
                );
                var authnrData = new DataView(authnrDataBuf);
                var offset = 0;

                // copy RPID
                var rpid = new Uint8Array(rpIdHash);
                for (let i = 0; i < 32; i++) {
                    authnrData.setUint8(i + offset, rpid[i]);
                }
                offset += 32;

                // set flags
                var flags = 0;
                flags |= 0x01; // TUP flag
                if (hasAd) flags |= 0x40; // AT flag
                if (hasEd) flags |= 0x80; // ED flag
                authnrData.setUint8(offset, flags);
                offset++;

                // set counter
                authnrData.setUint32(offset, counter, false);
                offset += 4;

                if (hasAd) {
                    var ad = new Uint8Array(attData);
                    for (let i = 0; i < attData.byteLength; i++) {
                        authnrData.setUint8(offset + i, ad[i]);
                    }
                    offset += attData.byteLength;
                }

                return authnrDataBuf;
            });
    }

    function createSignature(keyPair, authnrData, clientDataHash) {
        console.log("Signing");
        printHex("authnrData", authnrData);
        printHex("clientDataHash", clientDataHash);
        var sigDataBuf = new ArrayBuffer(
            authnrData.byteLength +
            clientDataHash.byteLength
        );
        var sigData = new Uint8Array(sigDataBuf);

        // copy authenticator data
        var ad = new Uint8Array(authnrData);
        for (let i = 0; i < authnrData.byteLength; i++) {
            sigData[i] = ad[i];
        }

        // copy client data hash
        var cd = new Uint8Array(clientDataHash);
        var offset = authnrData.byteLength;
        for (let i = 0; i < clientDataHash.byteLength; i++) {
            sigData[offset + i] = cd[i];
        }

        printHex("sigData", sigData);

        // sign over the combination of authenticator and client data,
        // and return the Promise that will resolve to the result
        return window.crypto.subtle.sign({
                name: "RSASSA-PKCS1-v1_5",
            },
            keyPair.privateKey,
            sigDataBuf
        ).then((sig) => {
            printHex("sig", sig);
            return sig;
        });
    }

    function _createPackedAttestation(rpIdHash, clientDataHash, credObj, opts) {
        var authnrData;
        console.log(credObj);

        printHex("client data hash", clientDataHash);

        // create authenticator data, create a signature, then form a packed attestation
        var opts = {
            attestation: true,
            extensions: false
        };
        return createAuthenticatorData(rpIdHash, credObj, opts)
            .then((ad) => {
                authnrData = ad;
                var p = createSignature(credObj.keyPair, authnrData, clientDataHash);
                assert.instanceOf(p, Promise);
                return p;
            })
            .then((sig) => {
                var attestationObject = {
                    fmt: "packed",
                    authData: new Uint8Array(authnrData),
                    attStmt: {
                        alg: credObj.jwk.alg,
                        sig: new Uint8Array(sig)
                    }
                };

                console.log("doing CBOR encode of attestation:", attestationObject);
                return CBOR.encode(attestationObject);
            })
            .then((cbor) => {
                return {
                    format: "packed",
                    attestation: cbor,
                    authenticatorData: authnrData
                };
            });
    }

    function _buf2hex(buffer) { // buffer is an ArrayBuffer
        return Array.prototype.map.call(new Uint8Array(buffer), x => ('00' + x.toString(16)).slice(-2)).join('');
    }

    // borrowed from:
    // https://github.com/niklasvh/base64-arraybuffer/blob/master/lib/base64-arraybuffer.js
    // modified to base64url by Yuriy :)
    /*
     * base64-arraybuffer
     * https://github.com/niklasvh/base64-arraybuffer
     *
     * Copyright (c) 2012 Niklas von Hertzen
     * Licensed under the MIT license.
     */
    var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    // Use a lookup table to find the index.
    var lookup = new Uint8Array(256);
    for (var i = 0; i < chars.length; i++) {
        lookup[chars.charCodeAt(i)] = i;
    }

    function b64decode(base64) {
        var bufferLength = base64.length * 0.75,
            len = base64.length,
            i, p = 0,
            encoded1, encoded2, encoded3, encoded4;

        if (base64[base64.length - 1] === "=") {
            bufferLength--;
            if (base64[base64.length - 2] === "=") {
                bufferLength--;
            }
        }

        var arraybuffer = new ArrayBuffer(bufferLength),
            bytes = new Uint8Array(arraybuffer);

        for (i = 0; i < len; i += 4) {
            encoded1 = lookup[base64.charCodeAt(i)];
            encoded2 = lookup[base64.charCodeAt(i + 1)];
            encoded3 = lookup[base64.charCodeAt(i + 2)];
            encoded4 = lookup[base64.charCodeAt(i + 3)];

            bytes[p++] = (encoded1 << 2) | (encoded2 >> 4);
            bytes[p++] = ((encoded2 & 15) << 4) | (encoded3 >> 2);
            bytes[p++] = ((encoded3 & 3) << 6) | (encoded4 & 63);
        }

        return arraybuffer;
    }
    console.log("Loading soft authn...");
    navigator.authentication.addAuthenticator(new softAuthn());
})();

// borrowed from: https://github.com/paroga/cbor-js
/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Patrick Gansterer <paroga@paroga.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

(function(global, undefined) {
    "use strict";
    var POW_2_24 = 5.960464477539063e-8,
        POW_2_32 = 4294967296,
        POW_2_53 = 9007199254740992;

    function encode(value) {
        var data = new ArrayBuffer(256);
        var dataView = new DataView(data);
        var lastLength;
        var offset = 0;

        function prepareWrite(length) {
            var newByteLength = data.byteLength;
            var requiredLength = offset + length;
            while (newByteLength < requiredLength)
                newByteLength <<= 1;
            if (newByteLength !== data.byteLength) {
                var oldDataView = dataView;
                data = new ArrayBuffer(newByteLength);
                dataView = new DataView(data);
                var uint32count = (offset + 3) >> 2;
                for (var i = 0; i < uint32count; ++i)
                    dataView.setUint32(i << 2, oldDataView.getUint32(i << 2));
            }

            lastLength = length;
            return dataView;
        }

        function commitWrite() {
            offset += lastLength;
        }

        function writeFloat64(value) {
            commitWrite(prepareWrite(8).setFloat64(offset, value));
        }

        function writeUint8(value) {
            commitWrite(prepareWrite(1).setUint8(offset, value));
        }

        function writeUint8Array(value) {
            var dataView = prepareWrite(value.length);
            for (var i = 0; i < value.length; ++i)
                dataView.setUint8(offset + i, value[i]);
            commitWrite();
        }

        function writeUint16(value) {
            commitWrite(prepareWrite(2).setUint16(offset, value));
        }

        function writeUint32(value) {
            commitWrite(prepareWrite(4).setUint32(offset, value));
        }

        function writeUint64(value) {
            var low = value % POW_2_32;
            var high = (value - low) / POW_2_32;
            var dataView = prepareWrite(8);
            dataView.setUint32(offset, high);
            dataView.setUint32(offset + 4, low);
            commitWrite();
        }

        function writeTypeAndLength(type, length) {
            if (length < 24) {
                writeUint8(type << 5 | length);
            } else if (length < 0x100) {
                writeUint8(type << 5 | 24);
                writeUint8(length);
            } else if (length < 0x10000) {
                writeUint8(type << 5 | 25);
                writeUint16(length);
            } else if (length < 0x100000000) {
                writeUint8(type << 5 | 26);
                writeUint32(length);
            } else {
                writeUint8(type << 5 | 27);
                writeUint64(length);
            }
        }

        function encodeItem(value) {
            var i;

            if (value === false)
                return writeUint8(0xf4);
            if (value === true)
                return writeUint8(0xf5);
            if (value === null)
                return writeUint8(0xf6);
            if (value === undefined)
                return writeUint8(0xf7);

            switch (typeof value) {
                case "number":
                    if (Math.floor(value) === value) {
                        if (0 <= value && value <= POW_2_53)
                            return writeTypeAndLength(0, value);
                        if (-POW_2_53 <= value && value < 0)
                            return writeTypeAndLength(1, -(value + 1));
                    }
                    writeUint8(0xfb);
                    return writeFloat64(value);

                case "string":
                    var utf8data = [];
                    for (i = 0; i < value.length; ++i) {
                        var charCode = value.charCodeAt(i);
                        if (charCode < 0x80) {
                            utf8data.push(charCode);
                        } else if (charCode < 0x800) {
                            utf8data.push(0xc0 | charCode >> 6);
                            utf8data.push(0x80 | charCode & 0x3f);
                        } else if (charCode < 0xd800) {
                            utf8data.push(0xe0 | charCode >> 12);
                            utf8data.push(0x80 | (charCode >> 6) & 0x3f);
                            utf8data.push(0x80 | charCode & 0x3f);
                        } else {
                            charCode = (charCode & 0x3ff) << 10;
                            charCode |= value.charCodeAt(++i) & 0x3ff;
                            charCode += 0x10000;

                            utf8data.push(0xf0 | charCode >> 18);
                            utf8data.push(0x80 | (charCode >> 12) & 0x3f);
                            utf8data.push(0x80 | (charCode >> 6) & 0x3f);
                            utf8data.push(0x80 | charCode & 0x3f);
                        }
                    }

                    writeTypeAndLength(3, utf8data.length);
                    return writeUint8Array(utf8data);

                default:
                    var length;
                    if (Array.isArray(value)) {
                        length = value.length;
                        writeTypeAndLength(4, length);
                        for (i = 0; i < length; ++i)
                            encodeItem(value[i]);
                    } else if (value instanceof Uint8Array) {
                        writeTypeAndLength(2, value.length);
                        writeUint8Array(value);
                    } else {
                        var keys = Object.keys(value);
                        length = keys.length;
                        writeTypeAndLength(5, length);
                        for (i = 0; i < length; ++i) {
                            var key = keys[i];
                            encodeItem(key);
                            encodeItem(value[key]);
                        }
                    }
            }
        }

        encodeItem(value);

        if ("slice" in data)
            return data.slice(0, offset);

        var ret = new ArrayBuffer(offset);
        var retView = new DataView(ret);
        for (var i = 0; i < offset; ++i)
            retView.setUint8(i, dataView.getUint8(i));
        return ret;
    }

    function decode(data, tagger, simpleValue) {
        var dataView = new DataView(data);
        var offset = 0;

        if (typeof tagger !== "function")
            tagger = function(value) {
                return value;
            };
        if (typeof simpleValue !== "function")
            simpleValue = function() {
                return undefined;
            };

        function commitRead(length, value) {
            offset += length;
            return value;
        }

        function readArrayBuffer(length) {
            return commitRead(length, new Uint8Array(data, offset, length));
        }

        function readFloat16() {
            var tempArrayBuffer = new ArrayBuffer(4);
            var tempDataView = new DataView(tempArrayBuffer);
            var value = readUint16();

            var sign = value & 0x8000;
            var exponent = value & 0x7c00;
            var fraction = value & 0x03ff;

            if (exponent === 0x7c00)
                exponent = 0xff << 10;
            else if (exponent !== 0)
                exponent += (127 - 15) << 10;
            else if (fraction !== 0)
                return (sign ? -1 : 1) * fraction * POW_2_24;

            tempDataView.setUint32(0, sign << 16 | exponent << 13 | fraction << 13);
            return tempDataView.getFloat32(0);
        }

        function readFloat32() {
            return commitRead(4, dataView.getFloat32(offset));
        }

        function readFloat64() {
            return commitRead(8, dataView.getFloat64(offset));
        }

        function readUint8() {
            return commitRead(1, dataView.getUint8(offset));
        }

        function readUint16() {
            return commitRead(2, dataView.getUint16(offset));
        }

        function readUint32() {
            return commitRead(4, dataView.getUint32(offset));
        }

        function readUint64() {
            return readUint32() * POW_2_32 + readUint32();
        }

        function readBreak() {
            if (dataView.getUint8(offset) !== 0xff)
                return false;
            offset += 1;
            return true;
        }

        function readLength(additionalInformation) {
            if (additionalInformation < 24)
                return additionalInformation;
            if (additionalInformation === 24)
                return readUint8();
            if (additionalInformation === 25)
                return readUint16();
            if (additionalInformation === 26)
                return readUint32();
            if (additionalInformation === 27)
                return readUint64();
            if (additionalInformation === 31)
                return -1;
            throw "Invalid length encoding";
        }

        function readIndefiniteStringLength(majorType) {
            var initialByte = readUint8();
            if (initialByte === 0xff)
                return -1;
            var length = readLength(initialByte & 0x1f);
            if (length < 0 || (initialByte >> 5) !== majorType)
                throw "Invalid indefinite length element";
            return length;
        }

        function appendUtf16Data(utf16data, length) {
            for (var i = 0; i < length; ++i) {
                var value = readUint8();
                if (value & 0x80) {
                    if (value < 0xe0) {
                        value = (value & 0x1f) << 6 | (readUint8() & 0x3f);
                        length -= 1;
                    } else if (value < 0xf0) {
                        value = (value & 0x0f) << 12 | (readUint8() & 0x3f) << 6 | (readUint8() & 0x3f);
                        length -= 2;
                    } else {
                        value = (value & 0x0f) << 18 | (readUint8() & 0x3f) << 12 | (readUint8() & 0x3f) << 6 | (readUint8() & 0x3f);
                        length -= 3;
                    }
                }

                if (value < 0x10000) {
                    utf16data.push(value);
                } else {
                    value -= 0x10000;
                    utf16data.push(0xd800 | (value >> 10));
                    utf16data.push(0xdc00 | (value & 0x3ff));
                }
            }
        }

        function decodeItem() {
            var initialByte = readUint8();
            var majorType = initialByte >> 5;
            var additionalInformation = initialByte & 0x1f;
            var i;
            var length;

            if (majorType === 7) {
                switch (additionalInformation) {
                    case 25:
                        return readFloat16();
                    case 26:
                        return readFloat32();
                    case 27:
                        return readFloat64();
                }
            }

            length = readLength(additionalInformation);
            if (length < 0 && (majorType < 2 || 6 < majorType))
                throw "Invalid length";

            switch (majorType) {
                case 0:
                    return length;
                case 1:
                    return -1 - length;
                case 2:
                    if (length < 0) {
                        var elements = [];
                        var fullArrayLength = 0;
                        while ((length = readIndefiniteStringLength(majorType)) >= 0) {
                            fullArrayLength += length;
                            elements.push(readArrayBuffer(length));
                        }
                        var fullArray = new Uint8Array(fullArrayLength);
                        var fullArrayOffset = 0;
                        for (i = 0; i < elements.length; ++i) {
                            fullArray.set(elements[i], fullArrayOffset);
                            fullArrayOffset += elements[i].length;
                        }
                        return fullArray;
                    }
                    return readArrayBuffer(length);
                case 3:
                    var utf16data = [];
                    if (length < 0) {
                        while ((length = readIndefiniteStringLength(majorType)) >= 0)
                            appendUtf16Data(utf16data, length);
                    } else
                        appendUtf16Data(utf16data, length);
                    return String.fromCharCode.apply(null, utf16data);
                case 4:
                    var retArray;
                    if (length < 0) {
                        retArray = [];
                        while (!readBreak())
                            retArray.push(decodeItem());
                    } else {
                        retArray = new Array(length);
                        for (i = 0; i < length; ++i)
                            retArray[i] = decodeItem();
                    }
                    return retArray;
                case 5:
                    var retObject = {};
                    for (i = 0; i < length || length < 0 && !readBreak(); ++i) {
                        var key = decodeItem();
                        retObject[key] = decodeItem();
                    }
                    return retObject;
                case 6:
                    return tagger(decodeItem(), length);
                case 7:
                    switch (length) {
                        case 20:
                            return false;
                        case 21:
                            return true;
                        case 22:
                            return null;
                        case 23:
                            return undefined;
                        default:
                            return simpleValue(length);
                    }
            }
        }

        var ret = decodeItem();
        if (offset !== data.byteLength)
            throw "Remaining bytes";
        return ret;
    }

    var obj = {
        encode: encode,
        decode: decode
    };

    if (typeof define === "function" && define.amd)
        define("cbor/cbor", obj);
    else if (typeof module !== "undefined" && module.exports)
        module.exports = obj;
    else if (!global.CBOR)
        global.CBOR = obj;

})(this);

// TODO: remove this debug code
function printHex(msg, buf) {
    // if the buffer was a TypedArray (e.g. Uint8Array), grab its buffer and use that
    if (ArrayBuffer.isView(buf) && buf.buffer instanceof ArrayBuffer) {
        buf = buf.buffer;
    }

    // check the arguments
    if ((typeof msg != "string") ||
        (typeof buf != "object")) {
        console.log("Bad args to printHex");
        return;
    }
    if (!(buf instanceof ArrayBuffer)) {
        console.log("Attempted printHex with non-ArrayBuffer:", buf);
        return;
    }
    // print the buffer as a 16 byte long hex string
    var arr = new Uint8Array(buf);
    var len = buf.byteLength;
    var i, str = "";
    console.log(msg);
    for (i = 0; i < len; i++) {
        var hexch = arr[i].toString(16);
        hexch = (hexch.length == 1) ? ("0" + hexch) : hexch;
        str += hexch.toUpperCase() + " ";
        if (i && !((i + 1) % 16)) {
            console.log(str);
            str = "";
        }
    }
    // print the remaining bytes
    if ((i) % 16) {
        console.log(str);
    }
}

/* JSHINT */
/* globals CBOR */
/* exported createCredential */