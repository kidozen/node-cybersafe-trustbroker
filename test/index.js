"use strict";
var assert = require("assert");
var TrustBroker = null;

describe("index", function() {
    it("was able to require module", function() {
        TrustBroker = require("../index.js");
        assert.ok(TrustBroker);
    });
});