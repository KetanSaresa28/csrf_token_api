require('dotenv').config();
const express = require('express')
const app = express()
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');

const PORT = process.env.PORT || 8080;
app.use(bodyParser.json());

// Get user agent and add to the request
app.use(function (req, res, next) {
  var agent = req.headers['user-agent']
  req.useragent = agent;
  res.header('Access-Control-Allow-Origin', req.headers.origin);
  res.header('Access-Control-Allow-Credentials', true);
  res.header('Access-Control-Allow-Methods', 'GET, PUT, POST, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Origin, version_number, Content-Type, Authorization, Content-Length, X-Requested-With, Accept, x-zumo-auth, sentry-trace, x-csrf-token');
  //intercepts OPTIONS method
  if ('OPTIONS' === req.method) {
    //respond with 200
    res.sendStatus(200);
  }
  else {
    next();
  }
})

/* Add CSRF Middleware */
app.use(cookieParser());
const csrf = require('csurf');
const csrfProtection = csrf({ cookie: { maxAge: 60 * 60, path: "/", httpOnly: true, sameSite: 'none', secure: true } }); // expire after 30 days


/* Send CSRF token */
app.get('/api/csrf/token', csrfProtection, (req, res) => {
  res.cookie('mobile_csrf', req.csrfToken(), { expires: 60 * 60, path: "/", httpOnly: true, sameSite: 'none', secure: true });
  return res.json({ success: true, code: 200, data: { csrfToken: req.csrfToken() }, cookies: req.cookies, });
});

app.post('/api/submit', csrfProtection, (req, res) => {
  console.log('Submit request');
  return res.json({ success: true, code: 200, data: { headers: req.headers, body: req.body, url: req.originalUrl } });
});

app.get('/api/status', (req, res) => {
  return res.json({ success: true, code: 200, message: 'OK' });
});

// error catching middleware
app.use(function (err, req, res, next) {
  if (err.code === 'EBADCSRFTOKEN') {
    /* Handle invalid CSRF Token error */
    console.info("Invalid_CSRF_Token", {
      event: {
        Invalid_CSRF_Token: { api: req.originalUrl, obj: { body: req.body, headers: req.headers } }
      }
    });
    return res.status(403).send({
      msg: '403: Invalid CSRF Token!',
      obj: { body: req.body, headers: req.headers, url: req.originalUrl }
    });
  } else {
    res.status(500).send({
      msg: '500: Internal Server Error',
      error: err.toString(),
    });
    next();
  }
})


app.listen(PORT, () => {
  console.log(`Example app listening on port ${PORT}`)
});
