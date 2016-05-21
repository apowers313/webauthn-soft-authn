// IIFE for clean namespace
(function() {


    if (window.webauthn === undefined) {
        console.log("WebAuthn API not found, can't load authenticator.");
        return;
    }

    if (window.webauthn.fidoAuthenticator === undefined ||
        window.webauthn.addAuthenticator === undefined) {
        console.log("Unsupported version of WebAuthn API in use, can't load authenticator");
        return;
    }

    // extend the authenticator object
    softAuthn.prototype = new webauthn.fidoAuthenticator();

    function softAuthn(opt) {
        // TODO: manage options
        // -- crypto params
        // -- authn type (PIN, pop-up, none, etc.)
        // -- attestation type
        this.name = "bob";
        console.log ("Const Name:", this.name);
        this.preferredCrypto = "RSASSA-PKCS1-v1_5";

        // call superclass constructor
        webauthn.fidoAuthenticator.call(this, opt);
        // override base methods
        // this.authenticatorMakeCredential = authenticatorMakeCredential;
        // this.authenticatorGetAssertion = authenticatorGetAssertion;
        // this.authenticatorCancel = authenticatorCancel;

        return this;
    }

    function _dbInit() {
        return new Promise(function(resolve, reject) {
            // create IndexedDatabase for storing Cred IDs / RPIDs?
            console.log("creating database");
            var db;
            var request = indexedDB.open("scoped-cred-store", 2);
            request.onupgradeneeded = function() {
                console.log("upgrading database");
                var db = request.result;
                // var store = db.createObjectStore("creds", {
                //     keyPath: "rpId"
                // });
                // var idIdx = store.createIndex("by_id", "id", {
                //     unique: true
                // });
                // var tx = db.transaction("creds", "readonly");
                var store = request.transaction.objectStore("creds");

                console.log("putting ID 7");
                store.put({
                    rpId: "localhost",
                    id: "7",
                    counter: 0
                });
            };

            request.onsuccess = function() {
                console.log("success!");
                db = request.result;
                resolve(db);
            };

            // TODO: onerror
        });
    }

    function _dbCredLookup() {
        return new Promise(function(resolve, reject) {
            var db = this.db;
            var tx = db.transaction("creds", "readonly");

            var store = tx.objectStore("creds");
            var index = store.index("by_id");
            var request2 = index.get("7");
            request2.onsuccess = function() {
                var matching = request2.result;
                if (matching !== undefined) {
                    console.log("Found match:", matching);
                } else {
                    console.log("No match found.");
                }
                // db.close();

            };
        });
    }

    function _generateCredId() {
        return "42"; // TODO: something better
    }

    function _generateAttestation() {
        return null;
    }

    softAuthn.prototype.authenticatorMakeCredential = function (rpId, account, clientDataHash, cryptoParameters, blacklist, extensions) {
        return new Promise(function(resolve, reject) {
            console.log("!!! MAKE CREDENTIAL");
            // TODO: verify arguments
            // prompt for user permission
            // TODO: process extension data
            // create assymetric key pair
            console.log ("Name:", this.name);
            console.log ("Preferred Crypto:", this.preferredCrypto);
            window.crypto.subtle.generateKey({
                        // TODO: should be options for crypto, bits, hash, etc.
                        name: this.preferredCrypto,
                        modulusLength: 2048, //can be 1024, 2048, or 4096
                        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
                        hash: {
                            name: "SHA-256"
                        }, //can be "SHA-1", "SHA-256", "SHA-384", or "SHA-512"
                    },
                    false, //whether the key is extractable (i.e. can be used in exportKey)
                    ["sign", "verify"] //can be any combination of "sign" and "verify"
                )
                .then(function(key) {
                    //returns a keypair object
                    console.log(key);
                    console.log(key.publicKey);
                    console.log(key.privateKey);
                })
                .catch(function(err) {
                    console.error(err);
                });

            // export public key
            window.crypto.subtle.exportKey(
                    "jwk", //can be "jwk" (public or private), "spki" (public only), or "pkcs8" (private only)
                    publicKey //can be a publicKey or privateKey, as long as extractable was true
                )
                .then(function(keydata) {
                    //returns the exported key data
                    console.log(keydata);
                })
                .catch(function(err) {
                    console.error(err);
                });

            // create new attestation
            var clientDataHash = "12"; // TODO
            var attestation = _generateAttestation(clientDataHash);

            // create credential ID and new credential
            var cred = {
                type: this.preferredCrypto,
                id: _generateCredId()
            };

            // store credential ID and RP ID for future use
            // this.db.save(cred.id, rpId);

            // resolve with credential, publicKey, rawAttestation = { attestation.type, attestation.statement, attestation.clientData }
        }.bind(this));
    };

    softAuthn.prototype.authenticatorGetAssertion = function() {
        return Promise.reject(new Error("Not Implemented"));
        // TODO: verify arguments
        // lookup credentials by RP ID
        // filter found credentials by whitelist
        // prompt for user permission

        // create assertion
        // - set TUP flag in authenticator data
        // - load counter, bump counter, store counter
        // - TODO: process extensions
        // - create a single buffer with authenticatorData, clientDataHash and extensions
        // - sign assertion

        // window.crypto.subtle.sign({
        //             name: "RSASSA-PKCS1-v1_5",
        //         },
        //         key.privateKey, //from stored credential
        //         data //ArrayBuffer of data you want to sign
        //     )
        //     .then(function(signature) {
        //         //returns an ArrayBuffer containing the signature
        //         console.log(new Uint8Array(signature));
        //     })
        //     .catch(function(err) {
        //         console.error(err);
        //     });

        // resolve with credential, authenticatorData, signature
    };

    softAuthn.prototype.authenticatorCancel = function() {
        // not sure how to handle this... maybe throw? set flag and check above?
        return Promise.reject(new Error("Not Implemented"));
    };

    console.log("Loading soft authn...");
    window.webauthn.addAuthenticator(new softAuthn());
})();