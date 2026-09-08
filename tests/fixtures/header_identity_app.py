"""Feature 016: header-asserted identity fixture (the timesheet shape).

Layout: a small Express-style JavaScript service whose entire authentication is a
middleware trusting a request header, attached per route module:

    header-identity-app/
      package.json
      src/middleware/auth.js      <- trust point (CWE-290 anchor)
      src/middleware/verifyJwt.js <- deliberate safe pattern (real credential check)
      src/routes/clients.js       <- router.use(authenticateUser)
      src/routes/reports.js       <- router.use(authenticateUser)
      src/routes/account.js       <- router.get('/me', authenticateUser, ...)
      src/routes/admin.js         <- router.use(verifyJwt)  (safe: consistent guard)
      src/database/init.js        <- sqlite-style convenience calls (db.get/db.run)
      src/server.js

Ground truth (GROUND_TRUTH): exactly one finding, anchored at the middleware trust
function; both safe patterns MUST NOT be reported.
"""

from __future__ import annotations

import shutil
from pathlib import Path

APP_FILES: dict[str, str] = {
    "package.json": '{"name": "header-identity-app", "version": "1.0.0"}\n',
    "src/database/init.js": '''let db = null;

function getDatabase() {
  return db;
}

function initializeDatabase(database) {
  db = database;
}

module.exports = { getDatabase, initializeDatabase };
''',
    "src/middleware/auth.js": '''const { getDatabase } = require('../database/init');

// Seeded weakness: identity is asserted by a client-controlled header with no
// credential verification at all.
function authenticateUser(req, res, next) {
  const userEmail = req.headers['x-user-email'];

  if (!userEmail) {
    return res.status(401).json({ error: 'User email required' });
  }

  const db = getDatabase();

  db.get('SELECT email FROM users WHERE email = ?', [userEmail], (err, row) => {
    if (err) {
      return res.status(500).json({ error: 'Internal server error' });
    }

    if (!row) {
      db.run('INSERT INTO users (email) VALUES (?)', [userEmail], (insertErr) => {
        if (insertErr) {
          return res.status(500).json({ error: 'Failed to create user' });
        }
        req.userEmail = userEmail;
        next();
      });
    } else {
      req.userEmail = userEmail;
      next();
    }
  });
}

module.exports = { authenticateUser };
''',
    # Deliberate SAFE pattern: a real credential check, must never be reported.
    "src/middleware/verifyJwt.js": '''function verifyJwt(req, res, next) {
  const header = req.headers['authorization'] || '';
  const token = header.replace('Bearer ', '');
  if (!token) {
    return res.status(401).json({ error: 'token required' });
  }
  const payload = jwt.verify(token, process.env.JWT_SECRET);
  req.userId = payload.sub;
  next();
}

module.exports = { verifyJwt };
''',
    "src/routes/clients.js": '''const express = require('express');
const { authenticateUser } = require('../middleware/auth');
const { getDatabase } = require('../database/init');

const router = express.Router();

router.use(authenticateUser);

router.get('/', (req, res) => {
  const db = getDatabase();
  db.all('SELECT * FROM clients WHERE user_email = ?', [req.userEmail], (err, rows) => {
    res.json(rows || []);
  });
});

router.post('/', (req, res) => {
  const db = getDatabase();
  db.run('INSERT INTO clients (name, user_email) VALUES (?, ?)',
    [req.body.name, req.userEmail], () => res.status(201).json({ created: true }));
});

module.exports = router;
''',
    "src/routes/reports.js": '''const express = require('express');
const { authenticateUser } = require('../middleware/auth');
const { getDatabase } = require('../database/init');

const router = express.Router();

router.use(authenticateUser);

router.get('/summary', (req, res) => {
  const db = getDatabase();
  db.get('SELECT COUNT(*) AS n FROM entries WHERE user_email = ?',
    [req.userEmail], (err, row) => res.json(row || {}));
});

module.exports = router;
''',
    "src/routes/account.js": '''const express = require('express');
const { authenticateUser } = require('../middleware/auth');
const { getDatabase } = require('../database/init');

const router = express.Router();

router.get('/me', authenticateUser, (req, res) => {
  const db = getDatabase();
  db.get('SELECT email, created_at FROM users WHERE email = ?',
    [req.userEmail], (err, row) => res.json(row || {}));
});

module.exports = router;
''',
    "src/routes/admin.js": '''const express = require('express');
// Deliberate SAFE pattern: admin routes attach the real JWT guard, consistently.
const { verifyJwt } = require('../middleware/verifyJwt');

const router = express.Router();

router.use(verifyJwt);

router.get('/users', (req, res) => {
  res.json({ users: [] });
});

module.exports = router;
''',
    "src/server.js": '''const express = require('express');
const clientsRoutes = require('./routes/clients');
const reportsRoutes = require('./routes/reports');
const accountRoutes = require('./routes/account');
const adminRoutes = require('./routes/admin');

const app = express();
app.use(express.json());
app.use('/api/clients', clientsRoutes);
app.use('/api/reports', reportsRoutes);
app.use('/api/account', accountRoutes);
app.use('/api/admin', adminRoutes);

module.exports = app;
''',
}

#: Declared ground truth, asserted by tests rather than restated inline.
GROUND_TRUTH = {
    # CWE-290 anchor: the middleware trust function.
    "anchor_finding": {
        "file": "src/middleware/auth.js",
        "symbol": "authenticateUser",
        "cwe": "CWE-290",
    },
    # Deliberately safe patterns that MUST NOT be reported.
    "safe_symbols": ["verifyJwt"],
    # Graph expectations the deterministic stages must satisfy.
    "wired_edges": [
        ("src/routes/clients.js", "authenticateUser"),
        ("src/routes/reports.js", "authenticateUser"),
        ("src/routes/account.js", "authenticateUser"),
        ("src/routes/admin.js", "verifyJwt"),
    ],
    # The middleware must read as an attacker-controlled source.
    "source_symbols": ["authenticateUser"],
}


def build(root: Path) -> Path:
    """Materialize the fixture and return its root."""
    app_root = root / "header-identity-app"
    if app_root.exists():
        shutil.rmtree(app_root)
    for relative, content in APP_FILES.items():
        path = app_root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    return app_root
