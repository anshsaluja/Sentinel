'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');

async function withServer(handler, run) {
  const server = http.createServer(handler);
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    return await run(`http://127.0.0.1:${server.address().port}`);
  } finally {
    await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  }
}

for (const status of [301, 302, 303, 307, 308]) {
  test(`authenticated approval POST must not follow HTTP ${status} redirect`, async () => {
    let destinationHits = 0;
    let received = null;
    await withServer((req, res) => {
      if (req.url === '/approval') {
        const chunks = [];
        req.on('data', chunk => chunks.push(chunk));
        req.on('end', () => {
          received = {method: req.method, authorization: req.headers.authorization, contentType: req.headers['content-type'], body: Buffer.concat(chunks).toString()};
          res.writeHead(status, {Location: '/destination'});
          res.end();
        });
      } else if (req.url === '/destination') {
        destinationHits++;
        res.writeHead(200);
        res.end('unexpected');
      } else {
        res.writeHead(404);
        res.end();
      }
    }, async base => {
      await assert.rejects(fetch(`${base}/approval`, {
        method: 'POST',
        headers: {Authorization: 'Bearer test-only', 'Content-Type': 'application/json'},
        body: JSON.stringify({decision: 'approve'}),
        redirect: 'error'
      }), TypeError);
    });
    assert.deepEqual(received, {
      method: 'POST', authorization: 'Bearer test-only',
      contentType: 'application/json', body: '{"decision":"approve"}'
    });
    assert.equal(destinationHits, 0);
  });
}

for (const status of [200, 401, 403, 409]) {
  test(`redirect:error preserves non-redirect HTTP ${status} responses`, async () => {
    await withServer((_req, res) => {
      res.writeHead(status, {'Content-Type': 'application/json'});
      res.end(JSON.stringify({status}));
    }, async base => {
      const response = await fetch(base, {redirect: 'error'});
      assert.equal(response.status, status);
      assert.deepEqual(await response.json(), {status});
    });
  });
}
