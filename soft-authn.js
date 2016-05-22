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
        this.preferredCrypto = "RSASSA-PKCS1-v1_5";
        this.cryptoBits = 2048;
        this.dbName = "scoped-cred-store";
        this.dbTableName = "creds";
        this.debug = 1;
        this.confirmType = "ok"; // TODO: shouldn't be on the object

        // TODO: debug should be private and static to strip out some of these options in minified code?
        if (this.debug) {
            console.log ("IN DEBUG MODE");
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
            throw new Error ("Trying to delete undefined database");
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
                    keyPath: "rpId"
                });
                var idIdx = store.createIndex("by_id", "id", {
                    unique: true
                });
            };

            request.onsuccess = function() {
                console.log("Database created!");
                credDb = request.result;
                return resolve(credDb);
            };

            request.onerror = function() {
                return reject(new Error ("Couldn't initialize DB"));
            };
        }.bind(this));
    }

    function _dbCredLookup() {
        return new Promise(function(resolve, reject) {
            var db = credDb;
            var tx = db.transaction("creds", "readonly");

            var store = tx.objectStore("creds");
            var index = store.index("by_id");
            var request = index.get("7");
            request.onsuccess = function() {
                var matching = request.result;
                if (matching !== undefined) {
                    console.log("Found match:", matching);
                } else {
                    console.log("No match found.");
                }
            };
        });
    }

    function _dbCredCreate(rpId, credId) {
        return new Promise(function(resolve, reject) {
            var db = credDb;
            var tx = db.transaction(this.dbTableName, "readwrite");
            var store = tx.objectStore(this.dbTableName);

            store.put ({
                rpId: rpId,
                id: credId,
                counter: 0
            });

            tx.oncomplete = function() {
                return resolve(true);
            };

            tx.onerror = function() {
                return reject (new Error ("Couldn't create credential"));
            };
        }.bind(this));
    }

    function _generateCredId() {
        return "42"; // TODO: something better
    }

    function _generateAttestation() {
        return null;
    }

    function _userConfirmation(rpId, rpDisplayName, displayName) {
        return new Promise(function(resolve, reject) {
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

            var publicKey;

            // prompt for user permission
            _userConfirmation.call(this, rpId, account.rpDisplayName, account.displayName)
                .then(function(res) { // create assymetric key pair and export public key
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
                .then(function(key) { // export public key                    
                    return window.crypto.subtle.exportKey("jwk", key.publicKey);
                })
                .then(function(jwkPk) { // dbInit
                    console.log("JWK Pk:", jwkPk);
                    publicKey = jwkPk;

                    return _dbInit.call(this);
                }.bind(this))
                .then(function(db) { // store credential ID and RP ID for future use
                    return _dbCredCreate.call(this, rpId, cred.id);
                }.bind(this))
                // TODO: _dbClose()?
                .then(function(x) { // resolve with credential, publicKey, rawAttestation = { attestation.type, attestation.statement, attestation.clientData }
                    return resolve({
                        credential: cred,
                        publicKey: publicKey,
                        attestation: attestation
                    });
                })
                .catch(function(err) {
                    console.error(err);
                    return reject (err);
                });

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