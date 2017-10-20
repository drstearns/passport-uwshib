"use strict";
/**
 * UW Shibboleth Passport Authentication Module
 *
 * This module exposes a passport Strategy object that is pre-configured to work with the UW's Shibboleth
 * Identity Provider (IdP). To use this, you must register your server with the UW IdP. For details, see
 * https://github.com/drstearns/passport-uwshib
 *
 * @module passport-uwshib
 * @author Dave Stearns
 */

var saml = require('passport-saml');
var util = require('util');

var uwIdPCert = 'MIID/TCCAuWgAwIBAgIJAMoYJbDt9lKKMA0GCSqGSIb3DQEBBQUAMFwxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJXQTEhMB8GA1UEChMYVW5pdmVyc2l0eSBvZiBXYXNoaW5ndG9uMR0wGwYDVQQDExRpZHAudS53YXNoaW5ndG9uLmVkdTAeFw0xMTA0MjYxOTEwMzlaFw0yMTA0MjMxOTEwMzlaMFwxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJXQTEhMB8GA1UEChMYVW5pdmVyc2l0eSBvZiBXYXNoaW5ndG9uMR0wGwYDVQQDExRpZHAudS53YXNoaW5ndG9uLmVkdTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMH9G8m68L0Hf9bmf4/7c+ERxgDQrbq50NfSi2YTQWc1veUIPYbZy1agSNuc4dwn3RtC0uOQbdNTYUAiVTcYgaYceJVB7syWf9QyGIrglZPMu98c5hWb7vqwvs6d3s2Sm7tBib2v6xQDDiZ4KJxpdAvsoPQlmGdgpFfmAsiYrnYFXLTHgbgCc/YhV8lubTakUdI3bMYWfh9dkj+DVGUmt2gLtQUzbuH8EU44vnXgrQYSXNQkmRcyoE3rj4Rhhbu/p5D3P+nuOukLYFOLRaNeiiGyTu3P7gtc/dy/UjUrf+pH75UUU7Lb369dGEfZwvVtITXsdyp0pBfun4CP808H9N0CAwEAAaOBwTCBvjAdBgNVHQ4EFgQUP5smx3ZYKODMkDglkTbduvLcGYAwgY4GA1UdIwSBhjCBg4AUP5smx3ZYKODMkDglkTbduvLcGYChYKReMFwxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJXQTEhMB8GA1UEChMYVW5pdmVyc2l0eSBvZiBXYXNoaW5ndG9uMR0wGwYDVQQDExRpZHAudS53YXNoaW5ndG9uLmVkdYIJAMoYJbDt9lKKMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQADggEBAEo7c2CNHEI+Fvz5DhwumU+WHXqwSOK47MxXwNJVpFQ9GPR2ZGDAq6hzLJLAVWcY4kB3ECDkRtysAWSFHm1roOU7xsU9f0C17QokoXfLNC0d7KoivPM6ctl8aRftU5moyFJkkJX3qSExXrl053uxTOQVPms4ypkYv1A/FBZWgSC8eNoYnBnv1Mhy4m8bfeEN7qT9rFoxh4cVjMH1Ykq7JWyFXLEB4ifzH4KHyplt5Ryv61eh6J1YPFa2RurVTyGpHJZeOLUIBvJu15GzcexuDDXe0kg7sHD6PbK0xzEF/QeXP/hXzMxR9kQXB/IR/b2k4ien+EM3eY/ueBcTZ95dgVM=';
var uwIdPEntryPoint = 'https://idp.u.washington.edu/idp/profile/SAML2/Redirect/SSO';
var strategyName = 'uwsaml';

/**
 * Standard URLs for Shibboleth Metadata route and the UW Logout page
 * You can use the urls.metadata in conjunction with the metadataRoute
 * function to create your server's metadata route implementation.
 *
 * @type {{metadata: string, uwLogoutUrl: string}}
 */
module.exports.urls = {
    metadata: '/Shibboleth.sso/Metadata',
    uwLogoutUrl: 'https://idp.u.washington.edu/idp/logout'
};

//map of possible profile attributes and what name
//we should give them on the resulting user object
//add to this with other attrs if you request them
var profileAttrs = {
    'urn:oid:0.9.2342.19200300.100.1.1': 'netId',
    'urn:oid:2.16.840.1.113730.3.1.241': 'displayName',
    'urn:oid:1.3.6.1.4.1.5923.1.1.1.1': 'affiliation',
    'urn:oid:2.5.4.3': 'cn',
    'urn:oid:0.9.2342.19200300.100.1.3': 'email',
    'urn:oid:2.16.840.1.113730.3.1.3': 'empNum',
    'urn:oid:1.3.6.1.4.1.5923.1.1.1.6': 'principalName',
    'urn:oid:2.5.4.42': 'givenName',
    'urn:oid:2.5.4.18': 'box',
    'urn:oid:2.5.4.20': 'phone',
    'urn:oid:2.5.4.4': 'surname',
    'urn:oid:2.5.4.12': 'title',
    'urn:oid:1.2.840.113994.200.21': 'studentId',
    'urn:oid:1.2.840.113994.200.24': 'regId',
    'urn:oid:1.3.6.1.4.1.5923.1.5.1.1': 'gwsGroups'
};

function verifyProfile(profile, done) {
    if (!profile) {
        return done(new Error('Empty SAML profile returned!'));
    }
    return done(null, convertProfileToUser(profile));
}

function convertProfileToUser(profile) {
    var user = {};
    var niceName;
    var idx;
    var keys = Object.keys(profile);
    var key;

    for (idx = 0; idx < keys.length; ++idx) {
        key = keys[idx];
        niceName = profileAttrs[key];
        if (niceName) {
            user[niceName] = profile[key];
        }
    }

    return user;
}

/**
 * Passport Strategy for UW Shibboleth Authentication
 *
 * This class extends passport-saml.Strategy, providing the necessary options for the UW Shibboleth IdP
 * and converting the returned profile into a user object with sensible property names.
 *
 * @param {Object} options - Configuration options
 * @param {string} options.entityId - Your server's entity id (often same as domain name)
 * @param {string} options.domain - Your server's domain name
 * @param {string} options.callbackUrl - Relative URL for the login callback (we will add https:// and domain)
 * @param {string} options.privateKey - Optional private key for signing SAML requests
 * @constructor
 */
module.exports.Strategy = function (options) {
    options = options || {};
    options.entryPoint = options.entryPoint || uwIdPEntryPoint;
    options.cert = options.cert || uwIdPCert;
    options.identifierFormat = null;
    options.issuer = options.issuer || options.entityId || options.domain;
    options.callbackUrl = 'https://' + options.domain + options.callbackUrl;
    options.decryptionPvk = options.privateKey;
    options.privateCert = options.privateKey;


    saml.Strategy.call(this, options, verifyProfile);
    this.name = strategyName;
};


util.inherits(module.exports.Strategy, saml.Strategy);

/*
    Route implementation for the standard Shibboleth metadata route
    usage:
        var uwshib = require(...);
        var strategy = new uwshib.Strategy({...});
        app.get(uwshib.urls.metadata, uwshib.metadataRoute(strategy, myPublicCert));
*/

/**
 * Returns a route implementation for the standard Shibboleth metadata route.
 * common usage:
 *  var uwshib = reuqire('passport-uwshib');
 *  var myPublicCert = //...read public cert PEM file
 *  var strategy = new uwshib.Strategy({...});
 *  app.get(uwshib.urls.metadata, uwshib.metadataRoute(strategy, myPublicCert));
 *
 * @param strategy - The new Strategy object from this module
 * @param publicCert - Your server's public certificate (typically loaded from a PEM file)
 * @returns {Function} - Route implementation suitable for handing to app.get()
 */
module.exports.metadataRoute = function(strategy, publicCert) {
    return function(req, res) {
        res.type('application/xml');
        res.status(200).send(strategy.generateServiceProviderMetadata(publicCert));
    };
}; //metadataRoute

/**
 * Middleware for ensuring that the user has authenticated.
 * You can use this in two different ways. If you pass this to app.use(), it will secure all routes
 * that are added to the app after that. Or you can use this selectively on routes by adding it as
 * the first route handler function, like so:
 *  app.get('/secure/route', ensureAuth(loginUrl), function(req, res) {...});
 *
 * @param loginUrl - The URL to redirect to if the user is not authenticated
 * @returns {Function} - Middleware function that ensures authentication
 */
module.exports.ensureAuth = function(loginUrl) {
    return function(req, res, next) {
        if (req.isAuthenticated())
            return next();
        else {
            if (req.session) {
                req.session.authRedirectUrl = req.url;
            }
            else {
                console.warn('passport-uwshib: No session property on request!'
                    + ' Is your session store unreachable?');

            }
            res.redirect(loginUrl);
        }
    };
};

/*
    Middleware for redirecting back to the originally requested URL after
    a successful authentication. The ensureAuth() middleware above will
    capture the current URL in session state, and when your callback route
    is called, you can use this to get back to the originally-requested URL.
    usage:
        var uwshib = require(...);
        var strategy = new uwshib.Strategy({...});
        app.get('/login', passport.authenticate(strategy.name));
        app.post('/login/callback', passport.authenticate(strategy.name), uwshib.backtoUrl());
        app.use(uwshib.ensureAuth('/login'));
*/
/**
 * Middleware for redirecting back to the originally requested URL after a successful authentication.
 * The ensureAuth() middleware in this same module will capture the current URL in session state, and
 * you can use this method to get back to the originally-requested URL during your login callback route.
 * Usage:
 *  var uwshib = require('passport-uwshib');
 *  var strategy = new uwshib.Strategy({...});
 *  app.get('/login', passport.authenticate(strategy.name));
 *  app.post('/login/callback', passport.authenticate(strategy.name), uwshib.backToUrl());
 *  app.use(uwshib.ensureAuth('/login'));
 *  //...rest of routes
 *
 * @param defaultUrl - Optional default URL to use if no redirect URL is in session state (defaults to '/')
 * @returns {Function} - Middleware function that redirects back to originally requested URL
 */
module.exports.backToUrl = function(defaultUrl) {
    return function(req, res) {
        var url = defaultUrl || '/';
        if (req.session) {
            url = req.session.authRedirectUrl;
            delete req.session.authRedirectUrl;
        }
        res.redirect(url);
    };
};

