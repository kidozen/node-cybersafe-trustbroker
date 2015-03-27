"use strict";

require("simple-errors");
var _               = require("lodash");
var modulePath      = process.argv.indexOf("mockSap") > -1 ? "../test/mockSap.js" : "./Sap.js";
var Sap             = require(modulePath);
var Cache           = require("mem-cache");

var TRUSTED = "trusted";
var SSO2 = "SSO2";

var CLAIM_SAM_ACCOUNT_NAME = "claim-sam-account-name";
var CLAIM_DOMAIN_NAME = "claim-domain-name";

module.exports.create = function (config, cb) {
    if (!config || typeof config !== "object") return cb(new Error("configuration is missing or invalid."));

    if (!config[CLAIM_SAM_ACCOUNT_NAME] || typeof config[CLAIM_SAM_ACCOUNT_NAME] !== "string") return cb(new Error("property '" + CLAIM_SAM_ACCOUNT_NAME + "' is missing."));
    if (!config[CLAIM_DOMAIN_NAME] || typeof config[CLAIM_DOMAIN_NAME] !== "string") return cb(new Error("property '" + CLAIM_DOMAIN_NAME + "' is missing."));

    if (config.connectionType !== TRUSTED && config.connectionType !== SSO2) return cb(new Error("property 'connectionType' is missing or has an invalid value."));

    try {
        cb(null, new TrustBroker(config));
    } catch (e) {
        cb(e);
    }
};

function TrustBroker(config) {
    var logger = config.logger || require("winston");
    var userLookupSap = new Sap(config.userLookupSap);
    var credentialsByAdUser = new Cache({ timeout: config.timeout || null });
    var samAccountNameClaimType = config[CLAIM_SAM_ACCOUNT_NAME];
    var domainNameClaimType = config[CLAIM_DOMAIN_NAME];
    var getCredentialFromSap = config.connectionType === TRUSTED ? getCredentialForTrusted : getCredentialForSso2;


    this.getSapCredential = function (methodName, options, cb) {
        logger.verbose("'Invoke' was received - invoking getCredential");
        getCredential(options, function (err1, credential) {

            logger.verbose("getCredential response. err:", err1);
            logger.debug("\tcredential:", credential);
            cb(err1, credential);
        });
    };

    this.close = function (cb) {
        userLookupSap.close(function () {
            credentialsByAdUser.clean();
            cb();
        });
    };

    function getAdUser(request) {
        if (!request || !request._kidozen || !request._kidozen.userClaims) return null;

        var samAccountNameClaimValue = "";
        var domainNameClaimValue = "";

        request._kidozen.userClaims
        .map(function (c) {
            switch (c.type) {
                case samAccountNameClaimType:
                    samAccountNameClaimValue = c.value;
                    break;
                case domainNameClaimType:
                    domainNameClaimValue = c.value;
                    break;
            };
        });

        if (domainNameClaimValue) domainNameClaimValue = domainNameClaimValue.toUpperCase();
        if (samAccountNameClaimValue && domainNameClaimValue) return samAccountNameClaimValue + "@" + domainNameClaimValue;
        return samAccountNameClaimValue || domainNameClaimValue || null;
    };

    function getCredential(options, cb) {
        logger.verbose("getCredential");
        logger.debug("\t", options);

        // get AD user from user's claims
        var adUser = getAdUser(options);
        if (!adUser) return cb(new Error("User's claim was not found."));

        // searchs for an active credential for the users
        var credential = credentialsByAdUser.get(adUser);
        if (credential) return cb(null, credential);

        // the user does not have a credential, create a new one
        var sapOptions = _.clone(options);
        if (sapOptions._kidozen) delete sapOptions._kidozen;

        getCredentialFromSap(adUser, sapOptions, function (err, newCredential, timeout) {
            if (err || !newCredential) return cb(Error.create("Can not get credential.", { user: adUser }, err));

            credentialsByAdUser.set(adUser, newCredential, timeout);
            logger.verbose("Credential was added to caché.");
            cb(null, newCredential);
        });
    };

    function getCredentialForTrusted(adUser, options, cb) {
        logger.verbose("getCredentialForTrusted - adUser: " + adUser);
        logger.debug("\t", options);

        var methodName = "/CSTB/IMAP_GET_USERS";
        var body = { IDENTITY: adUser };

        userLookupSap.lookupMethod(methodName, function (err1, method) {
            logger.verbose("getCredentialForTrusted - lookupMethod. methodName: '" + methodName + "', method found: " + !!method + ", Error:", err1);

            if (err1 || !method) return cb(err1);

            method(body, function (err2, result) {
                logger.verbose("getCredentialForTrusted - Response from: '" + methodName + "'' Error:", err2);
                logger.debug("\tresult", result);

                if (err2) return cb(err2);
                if (result.EROR_CODE > 0) return cb(Error.create(result.ERROR_TEXT || "unknown error"));
                if (!result.COUNT || !result.SAP_USERS || !result.SAP_USERS.length) return cb(Error.create("No SAP users were returned for AD-user " + adUser ));

                // we must select first SAP user, always
                var sapUser = result.SAP_USERS[0];
                if (sapUser.LOGON_ALLOWED > 0) return cb(Error.create(getLogonAllowedDescription(sapUser)));

                var credential = {
                    extiddata: sapUser.SAP_USER,
                    client: sapUser.SAP_CLIENT
                };
                cb(null, credential);
            });
        });
    };

    function getCredentialForSso2(adUser, options, cb) {
        logger.verbose("getCredentialForSso2 - adUser: " + adUser);
        logger.debug("\t", options);

        var methodName = "/CSTB/IMAP_GET_USERS_SSO2";
        var body = { IDENTITY: adUser, CREATE_TICKET: 1 };

        userLookupSap.lookupMethod(methodName, function (err1, method) {
            logger.verbose("lookupMethod. methodName: '" + methodName + "', method found: " + !!method + ", Error:", err1);
            if (err1 || !method) return cb(err1);

            method(body, function (err2, result) {
                logger.verbose("method - Response from: '" + methodName + "'' Error:", err2);
                logger.debug("\tresult", result);

                if (err2) return cb(err2);
                if (result.ERROR_CODE > 0) return cb(Error.create(result.ERROR_TEXT || "unknown error"));
                if (!result.COUNT || !result.SAP_USERS || !result.SAP_USERS.length) return cb(Error.create("No SAP users were returned for AD-user " + adUser ));

                // we must select first SAP user, always
                var sapUser = result.SAP_USERS[0];
                if (sapUser.LOGON_ALLOWED > 0) return cb(Error.create(getLogonAllowedDescription(sapUser)));

                var credential = {
                    user: sapUser.SAP_USER,
                    mysapsso2: result.TICKET,
                    client: sapUser.SAP_CLIENT
                };

                var timeoutMilliseconds = null;
                if (result.TICKET_EXPIRY) {
                    var expiry = parseUtcDateFromYYYYMMDDHHMM(result.TICKET_EXPIRY);
                    timeoutMilliseconds = (new Date() - expiry) - 5000;
                }
                cb(null, credential, timeoutMilliseconds);
            });
        });
    };

    function getLogonAllowedDescription(sapUser) {
        var description;

        switch (sapUser.LOGON_ALLOWED) {
            case 0:
                description = "No error and the SAP User ID and SAP Client can be used to logon";
                break;
            case 21:
                description = "An error occurred when getting details of SAP User ID <user> in SAP Client <client>";
                break;
            case 22:
                description = "The CUA assignment is missing for SAP User ID <user> in SAP Client <client>";
                break;
            case 23:
                description = "The SAP User ID <user> in SAP Client <client> cannot be used to logon - (not Dialog or Service User)";
                break;
            case 24:
                description = "The SAP User ID <user> in SAP Client <client> is locked";
                break;
            case 25:
                description = "The SAP User ID <user> in SAP Client <client> is not valid at the moment.";
                break;
            default:
                description = "Unknown LOGON_ALLOWED value <logonAllowed>.";
                break;
        };

        return description
        .replace("<user>", "'" + sapUser.SAP_USER + "'")
        .replace("<client>", "" + sapUser.SAP_CLIENT)
        .replace("<logonAllowed>", "(" + sapUser.LOGON_ALLOWED + ")");
    };

    function parseUtcDateFromYYYYMMDDHHMM(strDate) {
        function get(index, length) {
            return parseInt(strDate.substr(index, length));
        };

        // UTC function:
        // - year 4 digits
        // - month between 0 and 11  <--- this is weird
        // - day between 1 and 31
        // - hour between  0 and 23
        // - minutes between 0 and 59
        return new Date(Date.UTC(get(0, 4), get(4, 2)-1, get(6, 2), get(8, 2), get(10, 2)));
    };
};