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
        this.name = "bob";
        this.preferredCrypto = "RSASSA-PKCS1-v1_5";
        this.cryptoBits = 2048;
        this.dbName = "scoped-cred-store";
        this.dbTableName = "creds";
        this.debug = 1;
        this.confirmType = "ok"; // TODO: shouldn't be on the object

        // TODO: debug should be private and static to strip out some of these options in minified code?
        if (this.debug) {
            console.log("IN DEBUG MODE");
            this.confirmType = "none";
            console.log("Deleting db:", this.dbName);
            // _dbDelete.call(this);
            f = _dbDelete.bind(this);
            f();
        }

        // call superclass constructor
        webauthn.fidoAuthenticator.call(this, opt);

        return this;
    }

    // private variable for credential database
    var credDb = null;

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

    function _dbInit() {
        if (credDb) {
            return Promise.resolve(credDb);
        }

        return new Promise(function(resolve, reject) {
            // create IndexedDatabase for storing Cred IDs / RPIDs?
            var request = indexedDB.open(this.dbName);

            request.onupgradeneeded = function() {
                console.log("Creating database...");
                db = request.result;
                var store = db.createObjectStore("creds", {
                    keyPath: "id"
                });
                var idIdx = store.createIndex("by_rpId", "rpId", {
                    unique: true
                });
            };

            request.onsuccess = function() {
                console.log("Database created!");
                credDb = request.result;
                return resolve(credDb);
            };

            request.onerror = function() {
                return reject(new Error("Couldn't initialize DB"));
            };
        }.bind(this));
    }

    // TODO: lookup is supposed to be by RP ID ("example.com")
    //       but databases are stored by origin ("https://subdomain.example.com:443")
    //       so I'm not sure that this is going to work as expected if there
    //       are multiple ports or subdomains that the credentials are supposed to work with
    function _dbCredLookup(rpId) {
        return new Promise(function(resolve, reject) {
            var db = credDb;
            var tx = db.transaction("creds", "readonly");

            var store = tx.objectStore("creds");
            var index = store.index("by_rpId");
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

    function _dbCredCreate(rpId, credId, keyPair) {
        return new Promise(function(resolve, reject) {
            var db = credDb;
            var tx = db.transaction(this.dbTableName, "readwrite");
            var store = tx.objectStore(this.dbTableName);

            // TODO: create credential ID here

            var newCred = {
                rpId: rpId,
                id: credId,
                keyPair: keyPair,
                counter: 0
            };
            console.log("Saving New Credential:", newCred);
            store.put(newCred);


            tx.oncomplete = function() {
                return resolve(true);
            };

            tx.onerror = function() {
                return reject(new Error("Couldn't create credential"));
            };
        }.bind(this));
    }

    function _generateCredId() {
        var newId = window.crypto.getRandomValues(new Uint8Array(16));
        var newHexId = "";
        for (let byte of newId) {
            newHexId += byte.toString(16);
        }
        console.log ("New Credential ID:", newHexId);
        return newHexId;
    }

    function _generateAttestation() {
        return null;
    }

    function _userConfirmation(rpId, rpDisplayName, displayName) {
        return new Promise(function(resolve, reject) {
            console.log("Name:", this.name);
            console.log("Confirmation Type:", this.confirmType);
            switch (this.confirmType) {
                case "ok":
                    var result = confirm("Would you like to create an new account?\n" +
                        "Service: " + rpDisplayName + "\n" +
                        "Website: " + rpId + "\n" +
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

        }.bind(this));
    }

    softAuthn.prototype.authenticatorMakeCredential = function(rpId, account, clientDataHash, cryptoParameters, blacklist, extensions) {
        return new Promise(function(resolve, reject) { // TODO: just reurn the inner promise
            // console.log("!!! MAKE CREDENTIAL");
            // console.log("RP ID:", rpId);
            // console.log("account", account);
            // console.log("clientDataHash", clientDataHash);
            // console.log("cryptoParams:", cryptoParameters);
            // console.log("blacklist:", blacklist);
            // console.log("extensions:", extensions);

            // TODO: verify arguments

            // TODO: process extension data

            // create new attestation
            var clientDataHash = "12"; // TODO
            var attestation = _generateAttestation(clientDataHash);

            // create credential ID and new credential
            var cred = {
                type: this.preferredCrypto,
                id: _generateCredId()
            };

            var keyPair, publicKey;

            // prompt for user permission
            _userConfirmation.call(this, rpId, account.rpDisplayName, account.displayName)
                .then(function(confirm) { // create assymetric key pair and export public key
                    return window.crypto.subtle.generateKey({
                            // TODO: should be options for crypto, bits, hash, etc.
                            name: this.preferredCrypto,
                            modulusLength: this.cryptoBits, //can be 1024, 2048, or 4096
                            publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
                            hash: {
                                name: "SHA-256" //can be "SHA-1", "SHA-256", "SHA-384", or "SHA-512"
                            },
                        },
                        false, ["sign", "verify"]
                    );
                }.bind(this))
                .then(function(keys) { // export public key
                    keyPair = keys;
                    return window.crypto.subtle.exportKey("jwk", keyPair.publicKey);
                })
                .then(function(jwkPk) { // dbInit
                    console.log("JWK Pk:", jwkPk);
                    publicKey = jwkPk;

                    return _dbInit.call(this);
                }.bind(this))
                .then(function(db) { // store credential ID and RP ID for future use
                    return _dbCredCreate.call(this, rpId, cred.id, keyPair);
                }.bind(this))
                // TODO: _dbClose()?
                .then(function() { // resolve with credential, publicKey, rawAttestation = { attestation.type, attestation.statement, attestation.clientData }
                    return resolve({
                        credential: cred,
                        publicKey: publicKey,
                        attestation: attestation
                    });
                })
                .catch(function(err) {
                    console.error(err);
                    return reject(err);
                });
        }.bind(this));
    };

    softAuthn.prototype.authenticatorGetAssertion = function(rpId, assertionChallenge, clientDataHash, whitelist, extensions) {
        return new Promise(function(resolve, reject) {
            console.log("authenticatorGetAssertion");

            // TODO: verify arguments
            console.log("clientDataHash is:", typeof clientDataHash);

            // TODO: process extensions

            // lookup credentials by RP ID
            console.log("RP ID:", rpId);
            var selectedCred, authenticatorData;
            return _dbInit()
                .then(function(db) {
                    return _dbCredLookup(rpId);
                })
                .then(function(cred) { // prompt for user permission
                    // TODO: filter found credentials by whitelist
                    // TODO: _userConfirmation should allow user to pick from an array of accounts
                    selectedCred = cred;
                    console.log("Using credential:", selectedCred);
                    return _userConfirmation.call(this, rpId, "SERVICE MISSING", "USER MISSING");
                }.bind(this))
                .then(function(confirm) { // create assertion
                    console.log("Creating assertion");
                    var SIG = {
                        TUP_FLAG: 0x01
                    }
                    console.log("Using credential:", selectedCred);
                    var baseSignature = new DataView(new ArrayBuffer(5));
                    // set TUP flag in authenticator data
                    baseSignature.setUint8(0, SIG.TUP_FLAG);
                    // bump counter, store counter
                    baseSignature.setUint32(1, selectedCred.counter + 1);

                    // TODO: create a single buffer with authenticatorData, clientDataHash and extensions

                    authenticatorData = baseSignature;
                    return baseSignature;
                })
                .then(function(authenticatorData) { // sign assertion
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
                }.bind(this))
                .then(function(signature) { // resolve with credential, authenticatorData, signature
                    console.log ("Signature length:", signature.byteLength);
                    var ret = {
                        credential: {
                            id: selectedCred.id,
                            type: "ScopedCred" // TODO: need to be more intelligent about this?
                        },
                        authenticatorData: authenticatorData,
                        signature: signature
                    };
                    console.log("All done", ret);
                    return resolve(ret);
                })
                .catch(function(err) {
                    console.log("error in authenticatorGetAssertion:", err);
                    return reject(err);
                });
        }.bind(this));
    };

    softAuthn.prototype.authenticatorCancel = function() {
        // not sure how to handle this... maybe throw? set flag and check above?
        return Promise.reject(new Error("Not Implemented"));
    };

    console.log("Loading soft authn...");
    window.webauthn.addAuthenticator(new softAuthn());
})();