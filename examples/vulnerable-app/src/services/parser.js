// DEMO ONLY: uses lodash.merge on untrusted input (reachable path to lodash).
const _ = require('lodash');
const { v4: uuidv4 } = require('uuid');

const DEFAULTS = { role: 'user', active: true, profile: {} };

function buildUserRecord(input) {
  const base = { id: uuidv4(), ...DEFAULTS };
  return _.merge(base, input);
}

module.exports = { buildUserRecord };
