// DEMO ONLY: deliberately vulnerable application used by SupplyGuard.
const express = require('express');
const usersRouter = require('./routes/users');

const app = express();
app.use(express.json());

app.get('/api/health', (req, res) => res.json({ status: 'ok' }));
app.use('/api/users', usersRouter);

const PORT = process.env.PORT || 3000;
if (require.main === module) {
  app.listen(PORT, () => console.log(`demo app listening on ${PORT}`));
}

module.exports = app;
