const express = require('express');
const router = express.Router();
const email = require('emailjs');
const _ = require('lodash');
const bcrypt = require('bcrypt');
const fs = require('fs');
const Handlebars = require('handlebars');

const validateParams = require('./validate_params');
const Register = require('./register');
const Activate = require('./activate');
const Login = require('./login');
const AdminLogin = require('./admin_login');
const Logout = require('./logout');
const PasswordReset = require('./password_reset');
const PasswordResetConfirm = require('./password_reset_confirm');
const PasswordChange = require('./password_change');
const Authorize = require('./authorize');
const CreateUser = require('./create_user');
const UpdateUser = require('./update_user');
const Migrate = require('sf-rethink-migrate');

const ERR_INSUFFICIENT_PERMS = 'Insufficient permissions';

module.exports = (r, settings) => {
  this.r = r;

  this.settings = _.merge({
    // security
    secret: 'MY_SUPER_DUPER_SECRET',

    // storage
    migrate: true,                      // create tables and indices automatically

    // auth environment
    multitenancy: false,                // organization level support
    confirmEmail: true,                 // require email confirmation before login
    tokenExpiration: 1000 * 3600 * 24,  // default token expiration (24h)

    // email
    email: {
      from: "no-reply@foo.com",
      host: "localhost",
      user: "",
      password: "",
      ssl: false
    },

    // site setup
    site: {
      name: 'NAME THIS SITE!',          // used for templates
      url: 'http://localhost:8000'      // used for link generation
    },

    // email templates
    emails: {
      active: {
        subject: 'Your account is now fully active',
        template: Handlebars.compile(fs.readFileSync(__dirname + '/templates/active.html', 'utf-8'))
      },
      confirm: {
        subject: 'Confirm you email address',
        template: Handlebars.compile(fs.readFileSync(__dirname + '/templates/confirm.html', 'utf-8'))
      },      
      passwordChange: {
        subject: 'Your password has been changed',
        template: Handlebars.compile(fs.readFileSync(__dirname + '/templates/password_change.html', 'utf-8'))
      },
      passwordReset: {
        subject: 'Please confirm your password reset request',
        template: Handlebars.compile(fs.readFileSync(__dirname + '/templates/password_reset.html', 'utf-8'))
      },
      passwordResetConfirm: {
        subject: 'Your password has been reset',
        template: Handlebars.compile(fs.readFileSync(__dirname + '/templates/password_reset_confirm.html', 'utf-8'))
      }
    }
  }, settings);
  
  this.email = email.server.connect(this.settings.email);
  
  this.authorize = Authorize(r, this.settings);

  this.requireAdmin = (req, res, next) => {    
    if (req.auth.user.role !== 'admin') {
      res.status(403).send(ERR_INSUFFICIENT_PERMS);
    } else {
      next();
    }
  };

  this.requireSuperuser = (req, res, next) => {
    if (req.auth.user.role === 'user') {
      res.status(403).send(ERR_INSUFFICIENT_PERMS);
    } else {
      next();
    }
  };

  this.router = router;

  // account management
  this.router.post('/register', Register(r, this.email, this.settings));
  this.router.get('/activate', Activate(r, this.email, this.settings));

  // session management
  this.router.get('/', this.authorize, (req, res) => { res.send(req.auth); });
  this.router.post('/login', Login(r, this.settings));
  this.router.post('/admin/login', this.authorize, this.requireAdmin, AdminLogin(r, this.settings));
  this.router.get('/logout', this.authorize, Logout(r, this.settings));

  // password management
  this.router.get('/password_reset', PasswordReset(r, this.email, this.settings));
  this.router.get('/password_reset_confirm', PasswordResetConfirm(r, this.email, this.settings));
  this.router.post('/password_change', this.authorize, PasswordChange(r, this.email, this.settings));
  
  // user management
  this.router.post('/users', this.authorize, this.requireSuperuser, CreateUser(r));
  this.router.put('/users/:id', this.authorize, this.requireSuperuser, UpdateUser(r));

  if (this.settings.migrate) {
    const map = {
      users: [ "email", "perishableToken", "organization_id", "createdAt" ]
    };

    if (this.settings.multitenancy) {
      map.users.push('organization_id');
      map.organizations = [ "name", "createdAt" ];
    }

    this.migrate = Migrate(r, map).migrate;
  }

  return this;
};
