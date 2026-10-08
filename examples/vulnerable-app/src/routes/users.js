// DEMO ONLY: internet-facing route that passes user input into lodash.merge.
const express = require('express');
const { buildUserRecord } = require('../services/parser');

const router = express.Router();

router.post('/', (req, res) => {
  const record = buildUserRecord(req.body);
  res.status(201).json(record);
});

module.exports = router;
