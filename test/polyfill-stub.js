/**
 * This file creates a fake interface for adding the soft authenticator.
 * It's only purpose is to grab the authentication that is created so that
 * the interfaces can be tested.
 */

var authnrUnderTest = null;
// IIFE for clean namespace
(function() {
    var oldAddAuthenticator = navigator.authentication.addAuthenticator;
    navigator.authentication.addAuthenticator = function(authnr) {
        console.log("Catching authenticator to be tested...");
        authnrUnderTest = authnr;
        oldAddAuthenticator.call(navigator.authentication, authnr);
    };
})();