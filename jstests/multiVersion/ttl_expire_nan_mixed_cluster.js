/**
 * Tests that a mixed cluster in FCV 4.4 containing a TTL index with NaN for 'expireAfterSeconds'
 * will successfully replicate the TTL index to a secondary running a 5.0+ binary.
 *
 * @tags: [
 *     requires_replication,
 * ]
 */
(function() {
'use strict';

load('jstests/noPassthrough/libs/index_build.js');

const rst = new ReplSetTest({
    nodes: [{binVersion: 'last-lts'}, {binVersion: 'latest', rsConfig: {votes: 0, priority: 0}}],
});
rst.startSet();
rst.initiate();

let primary = rst.getPrimary();
const db = primary.getDB('test');
const coll = db.t;

assert.commandWorked(coll.createIndex({t: 1}, {expireAfterSeconds: NaN}));
assert.commandWorked(coll.insert({_id: 0, t: ISODate()}));

rst.awaitReplication();
const secondary = rst.getSecondary();
const secondaryColl = secondary.getCollection(coll.getFullName());
const secondaryIndexes = IndexBuildTest.assertIndexes(secondaryColl, 2, ['_id_', 't_1']);
const secondaryTTLIndex = secondaryIndexes.t_1;
assert(secondaryTTLIndex.hasOwnProperty('expireAfterSeconds'), tojson(secondaryTTLIndex));
assert.gt(secondaryTTLIndex.expireAfterSeconds, 0, tojson(secondaryTTLIndex));

rst.stopSet();
})();
