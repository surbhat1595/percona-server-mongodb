/**
 * Tests that upgrading time-series collections created using the last-lts binary warns about
 * potentially mixed-schema data when building secondary indexes on time-series measurements on the
 * latest binary. Additionally, tests that downgrading FCV from 5.2 removes the
 * 'timeseriesBucketsMayHaveMixedSchemaData' catalog entry flag from time-series collections.
 */
(function() {
"use strict";

load("jstests/core/timeseries/libs/timeseries.js");
load("jstests/multiVersion/libs/multi_rs.js");

const oldVersion = "last-lts";
const nodes = {
    n1: {binVersion: oldVersion},
    n2: {binVersion: oldVersion}
};

const rst = new ReplSetTest({nodes: nodes});
rst.startSet();
rst.initiate();

const dbName = "test";
const collName = jsTestName();

let primary = rst.getPrimary();
let db = primary.getDB(dbName);
let coll = db.getCollection(collName);

// Create a time-series collection while using older binaries.
const timeField = "time";
const metaField = "meta";
assert.commandWorked(
    db.createCollection(collName, {timeseries: {timeField: timeField, metaField: metaField}}));

assert.commandWorked(coll.insert({[timeField]: ISODate(), [metaField]: 1, x: 1}));
assert.commandWorked(coll.insert({[timeField]: ISODate(), [metaField]: 1, x: {y: "z"}}));
assert.commandWorked(coll.insert({[timeField]: ISODate(), [metaField]: 1, x: "abc"}));

jsTest.log("Upgrading replica set from last-lts to latest");
rst.upgradeSet({binVersion: "latest", setParameter: {logComponentVerbosity: tojson({storage: 1})}});

primary = rst.getPrimary();
db = primary.getDB(dbName);
coll = db.getCollection(collName);

if (!TimeseriesTest.timeseriesMetricIndexesEnabled(primary)) {
    jsTest.log("Skipping test as the featureFlagTimeseriesMetricIndexes feature flag is disabled");
    rst.stopSet();
    return;
}

// Building indexes on time-series measurements is only supported in FCV >= 5.2.
jsTest.log("Setting FCV to 'latestFCV'");
assert.commandWorked(primary.adminCommand({setFeatureCompatibilityVersion: latestFCV}));

const bucketCollName = dbName + ".system.buckets." + collName;

// The FCV upgrade process adds the catalog entry flag to time-series collections.
const secondary = rst.getSecondary();
assert(checkLog.checkContainsWithCountJson(primary, 6057601, {setting: true}, /*expectedCount=*/1));
assert(
    checkLog.checkContainsWithCountJson(secondary, 6057601, {setting: true}, /*expectedCount=*/1));

assert.commandWorked(coll.createIndex({[timeField]: 1}, {name: "time_1"}));
assert(checkLog.checkContainsWithCountJson(
    primary, 6057502, {namespace: bucketCollName}, /*expectedCount=*/0));

assert.commandWorked(coll.createIndex({[metaField]: 1}, {name: "meta_1"}));
assert(checkLog.checkContainsWithCountJson(
    primary, 6057502, {namespace: bucketCollName}, /*expectedCount=*/0));

assert.commandFailedWithCode(coll.createIndex({x: 1}, {name: "x_1"}), ErrorCodes.CannotCreateIndex);

// May have mixed-schema data.
assert(checkLog.checkContainsWithCountJson(
    primary, 6057502, {namespace: bucketCollName}, /*expectedCount=*/1));

// Mixed-schema data detected.
assert(checkLog.checkContainsWithCountJson(
    primary, 6057700, {namespace: bucketCollName}, /*expectedCount=*/1));

assert.commandFailedWithCode(coll.createIndex({[timeField]: 1, x: 1}, {name: "time_1_x_1"}),
                             ErrorCodes.CannotCreateIndex);

// May have mixed-schema data.
assert(checkLog.checkContainsWithCountJson(
    primary, 6057502, {namespace: bucketCollName}, /*expectedCount=*/2));

// Mixed-schema data detected.
assert(checkLog.checkContainsWithCountJson(
    primary, 6057700, {namespace: bucketCollName}, /*expectedCount=*/2));

// Check that the catalog entry flag doesn't get set to false.
assert(
    checkLog.checkContainsWithCountJson(primary, 6057601, {setting: false}, /*expectedCount=*/0));
assert(
    checkLog.checkContainsWithCountJson(secondary, 6057601, {setting: false}, /*expectedCount=*/0));

// The FCV downgrade process removes the catalog entry flag from time-series collections.
jsTest.log("Setting FCV to 'lastLTSFCV'");
assert.commandWorked(primary.adminCommand({setFeatureCompatibilityVersion: lastLTSFCV}));
assert(checkLog.checkContainsWithCountJson(primary, 6057601, {setting: null}, /*expectedCount=*/1));
assert(
    checkLog.checkContainsWithCountJson(secondary, 6057601, {setting: null}, /*expectedCount=*/1));

rst.stopSet();
}());