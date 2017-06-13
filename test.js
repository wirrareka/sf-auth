process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

var chai = require('chai');
var chaiHttp = require('chai-http');
var should = chai.should();
var expect = chai.expect;

// test server
const express = require('express');
const bodyParser = require('body-parser');
const r = require('rethinkdbdash')({
  db: 'sf_auth_test'
});

const Token = require('./token');

const auth = require('./index')(r, {
  secret: process.env.SF_AUTH_SECRET,
  site: {
    name: 'Soundfile Auth Test Run',
    url: 'http://localhost:3090'
  },
  email: {
    from: process.env.SF_AUTH_MAIL_FROM,
    host: process.env.SF_AUTH_MAIL_HOST,
    user: process.env.SF_AUTH_MAIL_USER,
    password: process.env.SF_AUTH_MAIL_PASSWORD,
    ssl: true
  }
});

// Create default port
const PORT = 3099;

// Create a new app
const app = express();
app.use(bodyParser.json())
   .use(bodyParser.urlencoded({ extended: false }));

app.use('/auth', auth.router);

app.use('/test/authorize', auth.authorize, (req, res) => {
  res.send(req.auth);
});

app.use('/test/admin/authorize', auth.authorize, auth.requireAdmin, (req, res) => {
  res.send(req.auth);
});

// Attach your endpoints/controllers here

chai.use(chaiHttp);


describe('Registration', function() {

  before((done) => {
    auth.migrate(() => {
      auth.settings.multitenant = false;
      app.listen(PORT, () => {
        r.table('users').delete().then(() => {
          done();
        });
      });
    });      
  });

  // test register
  it('[POST /auth/register] should register', (done) => {
    chai
      .request(app)
      .post('/auth/register')
      .send({
        user: { 
          email: 'john@doe.com',
          firstName: 'John',
          lastName: 'Doe',
          password: 'testtest',        
          passwordConfirmation: 'testtest'
        }
      })
      .end(function(err, res) {        
        should.not.exist(err);
        res.should.have.status(200);
        res.should.be.json;
        res.body.should.be.a('object');
        res.body.user.should.be.a('object');
        should.not.exist(res.organization);
        res.body.user.should.include.keys(
          'id', 'email', 'createdAt', 'updatedAt', 'emailConfirmed'
        );
        res.body.user.emailConfirmed.should.eql(false);
        done();
      });
  }).timeout(5000);

  it('[POST /auth/register] should prevent registering user with existing email', (done) => {
    chai
      .request(app)
      .post('/auth/register')
      .send({
        user: { 
          email: 'john@doe.com',
          firstName: 'John',
          lastName: 'Doe',
          password: 'testtest',        
          passwordConfirmation: 'testtest'
        }
      })
      .end(function(err, res){        
        should.exist(err);
        res.should.have.status(500);
        res.text.should.eql('User is not unique');
        done();
      });
  });

  it('[POST /auth/register] should prevent registering user without email', (done) => {
    chai
      .request(app)
      .post('/auth/register')
      .send({
        user: { 
          firstName: 'John',
          lastName: 'Doe',
          password: 'testtest',        
          passwordConfirmation: 'testtest'
        }
      })
      .end(function(err, res){        
        should.exist(err);
        res.should.have.status(500);
        res.text.should.eql('Invalid Parameters');
        done();
      });
  });

  it('[POST /auth/register] should prevent registering without password', (done) => {
    chai
      .request(app)
      .post('/auth/register')
      .send({
        user: { 
          email: 'john@doe.com',
          firstName: 'John',
          lastName: 'Doe',
          passwordConfirmation: 'testtest'
        }
      })
      .end(function(err, res){        
        should.exist(err);
        res.should.have.status(500);
        res.text.should.eql('Invalid Parameters');
        done();
      });
  });

  it('[POST /auth/register] should prevent registering without password confirmation', (done) => {
    chai
      .request(app)
      .post('/auth/register')
      .send({
        user: { 
          email: 'john@doe.com',
          firstName: 'John',
          lastName: 'Doe',
          password: 'testtest'
        }
      })
      .end(function(err, res){        
        should.exist(err);
        res.should.have.status(500);
        res.text.should.eql('Invalid Parameters');
        done();
      });
  });

  it('[POST /auth/register] should prevent registering without proper confirmed password', (done) => {
    chai
      .request(app)
      .post('/auth/register')
      .send({
        user: { 
          email: 'john@doe.com',
          firstName: 'John',
          lastName: 'Doe',
          password: 'testtest',
          passwordConfirmation: 'wrong_password'
        }
      })
      .end(function(err, res){        
        should.exist(err);
        res.should.have.status(500);
        res.text.should.eql('Invalid Parameters');
        done();
      });
  });

});

describe('Email Confirmation', function() {

  let perishableToken = '';
  it('GET /auth/activate] should activate first time', (done) => {
    r.table('users')
      .filter({email: 'john@doe.com'})
      .then((results) => {               
        const user = results[0]; 
        perishableToken = user.perishableToken;
        chai
          .request(app)
          .get('/auth/activate?token=' + user.perishableToken)
          .end((err, res) => {
            expect(res).to.redirect;
            r.table('users')
            .get(user.id)
            .then((resultUser) => {   
                resultUser.should.be.a('object');
                resultUser.updatedAt.should.be.a('date');
                resultUser.updatedAt.should.not.eql(resultUser.createdAt);
                resultUser.emailConfirmed.should.eql(true);
                expect(resultUser.perishableToken).be.a('null');
                done();
            });            
          });
      });    
  });

  it('GET /auth/activate] should not allow multiple activations', (done) => {
    chai
      .request(app)
      .get('/auth/activate?token=' + perishableToken)
      .end((err, res) => {
        should.exist(err);
        err.message.should.eql('Forbidden');
        res.should.have.status(403);     
        done();   
      });
  });
  
  it('GET /auth/activate] should not allow activation if settings.confirmEmail = false', (done) => {
    chai
      .request(app)
      .get('/auth/activate?token=' + perishableToken)
      .end((err, res) => {
        should.exist(err);
        err.message.should.eql('Forbidden');
        res.should.have.status(403);     
        done();   
      });
  });

});

describe('Login', function() {

  it('[POST /auth/login] should login on', (done) => {
    chai
      .request(app)
      .post('/auth/login')
      .send({ email: 'john@doe.com', password: 'testtest' })
      .end((err, res) => {        
        should.not.exist(err);
        res.should.have.status(200);
        res.should.be.json;
        res.body.should.be.a('object');        
        res.body.user.should.include.keys(
          'id', 'email', 'createdAt', 'updatedAt', 'emailConfirmed'
        );
        done();
      });
  });

  it('[POST /auth/login] returns decodable token', (done) => {
    chai
      .request(app)
      .post('/auth/login')
      .send({ email: 'john@doe.com', password: 'testtest' })
      .end((err, res) => {
        should.not.exist(err);
        res.should.have.status(200);
        res.should.be.json;
        res.body.should.be.a('object');
        
        const encoded = res.body.token;
        const token = Token.decode(auth.settings, encoded);

        token.payload.should.include.keys(
          'user_id', 'issuedAt', 'expiresAt'
        );

        res.body.should.include.keys(
          'token', 'user'
        );

        res.body.user.should.include.keys(
          'id', 'email', 'createdAt', 'updatedAt', 'emailConfirmed'
        );
        done();
      });
  });

  it('[POST /auth/login] should not pass with invalid credentials', (done) => {
    chai
      .request(app)
      .post('/auth/login')
      .send({ email: 'john@doe.com', password: 'wrong_password' })
      .end(function(err, res) {
        should.exist(err);
        err.message.should.eql('Forbidden');
        res.should.have.status(403);
        done();
      });
  });

  it('[POST /auth/login] should not pass without email', (done) => {
    chai
      .request(app)
      .post('/auth/login')
      .send({ password: 'password' })
      .end(function(err, res) {
        should.exist(err);
        should.exist(res.text);
        res.text.should.eql('INVALID PARAMETERS');
        res.should.have.status(500);
        done();
      });
  });

});

describe('Request Authorization (without multitenancy)', function() {

  let loginBody = {};
  let loginHeaders = {};
  let authorizeBody = {};
  let authorizeHeaders = {};

  before((done) => {
    chai
      .request(app)
      .post('/auth/login')
      .send({ email: 'john@doe.com', password: 'testtest' })
      .end((err, res) => {        
        loginBody = res.body;
        loginHeaders = res.headers;
        done();
      });
  });


  it('[GET /test/authorize] should show allow authorized request', (done) => {
    chai
      .request(app)
      .get('/test/authorize')
      .set('Authorization', 'Bearer ' + loginBody.token)
      .end((err, res) => {        
        should.not.exist(err);
        res.should.have.status(200);
        res.should.be.json;
        res.body.should.be.a('object');        
        authorizeBody = res.body;
        authorizeHeaders = res.headers;
        res.body.user.should.include.keys(
          'id', 'email'
        );        
        done();
      });
  });

  it('[GET /test/authorize] should return token-exchange in response headers', (done) => {
    authorizeHeaders.should.include.keys(
      'token-exchange'
    );
    done();
  });

  it('[GET /test/authorize] should not support multitenancy', (done) => {
    authorizeBody.should.not.include.keys(
      'organization'
    );

    authorizeBody.user.should.not.include.keys(
      'organization_id'
    );
    done();
  });

  it('[GET /test/authorize] should not provide auth object with user password', (done) => {
    authorizeBody.user.should.not.include.keys(
      'password', 'passwordConfirmation'
    );
    done();
  });

  it('[GET /test/authorize] should not provide auth object with user perishableToken', (done) => {
    authorizeBody.user.should.not.include.keys(
      'perishableToken'
    );
    done();
  });

  it('[GET /test/authorize] should provide auth object with user having minimal attributes', (done) => {
    authorizeBody.user.should.include.keys(
      'id', 'email', 'createdAt', 'updatedAt'
    );
    done();
  });

});

describe('Password Change', function() {
  let loginBody = {};
  let loginHeaders = {};
  let authorizeBody = {};
  let authorizeHeaders = {};

  before((done) => {
    chai
      .request(app)
      .post('/auth/login')
      .send({ email: 'john@doe.com', password: 'testtest' })
      .end((err, res) => {
        loginBody = res.body;
        loginHeaders = res.headers;
        done();
      });
  });
  
  it('[POST /auth/password_change] should change password', (done) => {
    chai
      .request(app)
      .post('/auth/password_change')
      .set('Authorization', 'Bearer ' + loginBody.token)
      .send({ currentPassword: 'testtest', newPassword: 'testtest2' })
      .end((err, res) => {
        should.not.exist(err);
        res.should.have.status(200);
        res.should.be.json;
        res.body.should.be.a('object');
        res.body.should.include.keys(
          'success', 'message'
        );

        chai
          .request(app)
          .post('/auth/login')
          .send({ email: 'john@doe.com', password: 'testtest2' })
          .end((err, res) => {
            res.should.have.status(200);
            res.should.be.json;
            res.body.should.be.a('object');
            done();
          });
      });
  }).timeout(5000);

  it('[GET /auth/password_reset] should reset password', (done) => {
    chai
      .request(app)
      .get('/auth/password_reset?email=' + 'john@doe.com')
      .end((err, res) => {
        should.not.exist(err);
        res.should.have.status(200);
        res.should.be.json;
        res.body.should.be.a('object');
        res.body.should.include.keys(
          'success', 'message'
        );
        done();
      });
  }).timeout(5000);
  
  it('[GET /auth/password_reset_confirm] should confirm password reset', (done) => {
    r.table('users')
    .get(loginBody.user.id)
    .then((user) => {
      chai
        .request(app)
        .get('/auth/password_reset_confirm?token=' + user.perishableToken + '&email=john@doe.com')
        .end((err, res) => {
          should.not.exist(err);
          res.should.have.status(200);
          res.should.be.json;
          res.body.should.be.a('object');
          res.body.should.include.keys(
            'success', 'message'
          );
          done();
        });
    });    
  }).timeout(5000);

});

// multitenant

describe('Registration (MultiTenant)', function() {
  
  before((done) => {
    auth.settings.multitenancy = true;

    r.table('users').delete().then(() => {
      r.table('organizations').delete().then(() => {
        done();        
      });
    });
  });

  // test register
  it('[POST /auth/register] should register', (done) => {
    chai
      .request(app)
      .post('/auth/register')
      .send({
        user: { 
          email: 'john@doe.com',
          firstName: 'John',
          lastName: 'Doe',
          password: 'testtest',        
          passwordConfirmation: 'testtest'
        },
        organization: {
          name: 'Foobar Company'
        }
      })
      .end(function(err, res) {        
        should.not.exist(err);
        res.should.have.status(200);
        res.should.be.json;
        res.body.should.be.a('object');
        res.body.user.should.be.a('object');
        res.body.organization.should.be.a('object');
        should.not.exist(res.organization);
        res.body.should.include.keys(
          'user', 'organization'
        );
        res.body.user.should.include.keys(
          'id', 'email', 'createdAt', 'updatedAt', 'emailConfirmed'
        );
        res.body.user.emailConfirmed.should.eql(false);
        done();
      });
  }).timeout(5000);

  it('[POST /auth/register] should prevent registering user with existing email', (done) => {
    chai
      .request(app)
      .post('/auth/register')
      .send({
        user: { 
          email: 'john@doe.com',
          firstName: 'John',
          lastName: 'Doe',
          password: 'testtest',        
          passwordConfirmation: 'testtest'
        },
        organization: {
          name: 'Foobar Company 2'
        }
      })
      .end(function(err, res){        
        should.exist(err);
        res.should.have.status(500);
        res.text.should.eql('User is not unique');
        done();
      });
  });

  it('[POST /auth/register] should prevent registering user without email', (done) => {
    chai
      .request(app)
      .post('/auth/register')
      .send({
        user: { 
          firstName: 'John',
          lastName: 'Doe',
          password: 'testtest',        
          passwordConfirmation: 'testtest'
        },
        organization: {
          name: 'Foobar Company'
        }
      })
      .end(function(err, res){        
        should.exist(err);
        res.should.have.status(500);
        res.text.should.eql('Invalid Parameters');
        done();
      });
  });

  it('[POST /auth/register] should prevent registering without password', (done) => {
    chai
      .request(app)
      .post('/auth/register')
      .send({
        user: { 
          email: 'john@doe.com',
          firstName: 'John',
          lastName: 'Doe',
          passwordConfirmation: 'testtest'
        },
        organization: {
          name: 'Foobar Company'
        }
      })
      .end(function(err, res){        
        should.exist(err);
        res.should.have.status(500);
        res.text.should.eql('Invalid Parameters');
        done();
      });
  });

  it('[POST /auth/register] should prevent registering without password confirmation', (done) => {
    chai
      .request(app)
      .post('/auth/register')
      .send({
        user: { 
          email: 'john@doe.com',
          firstName: 'John',
          lastName: 'Doe',
          password: 'testtest'
        },
        organization: {
          name: 'Foobar Company'
        }
      })
      .end(function(err, res){        
        should.exist(err);
        res.should.have.status(500);
        res.text.should.eql('Invalid Parameters');
        done();
      });
  });

  it('[POST /auth/register] should prevent registering without proper confirmed password', (done) => {
    chai
      .request(app)
      .post('/auth/register')
      .send({
        user: { 
          email: 'john@doe.com',
          firstName: 'John',
          lastName: 'Doe',
          password: 'testtest',
          passwordConfirmation: 'wrong_password'
        },
        organization: {
          name: 'Foobar Company'
        }
      })
      .end(function(err, res){        
        should.exist(err);
        res.should.have.status(500);
        res.text.should.eql('Invalid Parameters');
        done();
      });
  });

});

describe('Email Confirmation (MultiTenant)', function() {

  let perishableToken = '';
  it('GET /auth/activate] should activate first time', (done) => {
    r.table('users')
      .filter({email: 'john@doe.com'})
      .then((results) => {               
        const user = results[0];         
        perishableToken = user.perishableToken;
        chai
          .request(app)
          .get('/auth/activate?token=' + user.perishableToken)
          .end((err, res) => {
            expect(res).to.redirect;
            r.table('users')
            .get(user.id)
            .then((resultUser) => {   
                resultUser.should.be.a('object');
                resultUser.updatedAt.should.be.a('date');
                resultUser.updatedAt.should.not.eql(resultUser.createdAt);
                resultUser.emailConfirmed.should.eql(true);
                expect(resultUser.perishableToken).be.a('null');
                done();
            });            
          });
      });    
  });

  it('GET /auth/activate] should not allow multiple activations', (done) => {
    chai
      .request(app)
      .get('/auth/activate?token=' + perishableToken)
      .end((err, res) => {
        should.exist(err);
        err.message.should.eql('Forbidden');
        res.should.have.status(403);     
        done();   
      });
  });
  
  it('GET /auth/activate] should not allow activation if settings.confirmEmail = false', (done) => {
    chai
      .request(app)
      .get('/auth/activate?token=' + perishableToken)
      .end((err, res) => {
        should.exist(err);
        err.message.should.eql('Forbidden');
        res.should.have.status(403);     
        done();   
      });
  });

});

describe('Login (MultiTenant)', function() {

  it('[POST /auth/login] should login on', (done) => {
    chai
      .request(app)
      .post('/auth/login')
      .send({ email: 'john@doe.com', password: 'testtest' })
      .end((err, res) => {        
        should.not.exist(err);
        res.should.have.status(200);
        res.should.be.json;
        res.body.should.be.a('object');        
        res.body.should.include.keys(
          'user', 'organization'
        );
        res.body.user.should.include.keys(
          'id', 'email', 'createdAt', 'updatedAt', 'emailConfirmed'
        );
        done();
      });
  });

  it('[POST /auth/login] returns decodable token', (done) => {
    chai
      .request(app)
      .post('/auth/login')
      .send({ email: 'john@doe.com', password: 'testtest' })
      .end((err, res) => {
        should.not.exist(err);
        res.should.have.status(200);
        res.should.be.json;
        res.body.should.be.a('object');
        
        const encoded = res.body.token;
        const token = Token.decode(auth.settings, encoded);

        token.payload.should.include.keys(
          'user_id', 'issuedAt', 'expiresAt'
        );

        res.body.should.include.keys(
          'token', 'user'
        );

        res.body.user.should.include.keys(
          'id', 'email', 'createdAt', 'updatedAt', 'emailConfirmed'
        );
        done();
      });
  });

  it('[POST /auth/login] should not pass with invalid credentials', (done) => {
    chai
      .request(app)
      .post('/auth/login')
      .send({ email: 'john@doe.com', password: 'wrong_password' })
      .end(function(err, res) {
        should.exist(err);
        err.message.should.eql('Forbidden');
        res.should.have.status(403);
        done();
      });
  });

  it('[POST /auth/login] should not pass without email', (done) => {
    chai
      .request(app)
      .post('/auth/login')
      .send({ password: 'password' })
      .end(function(err, res) {
        should.exist(err);
        should.exist(res.text);
        res.text.should.eql('INVALID PARAMETERS');
        res.should.have.status(500);
        done();
      });
  });

});

describe('Request Authorization (MultiTenant)', function() {

  let loginBody = {};
  let loginHeaders = {};
  let authorizeBody = {};
  let authorizeHeaders = {};

  before((done) => {
    chai
      .request(app)
      .post('/auth/login')
      .send({ email: 'john@doe.com', password: 'testtest' })
      .end((err, res) => {        
        loginBody = res.body;
        loginHeaders = res.headers;
        done();
      });
  });


  it('[GET /test/authorize] should show allow authorized request', (done) => {
    chai
      .request(app)
      .get('/test/authorize')
      .set('Authorization', 'Bearer ' + loginBody.token)
      .end((err, res) => {        
        should.not.exist(err);
        res.should.have.status(200);
        res.should.be.json;
        res.body.should.be.a('object');        
        authorizeBody = res.body;
        authorizeHeaders = res.headers;
        res.body.should.include.keys(
          'user', 'organization'
        );
        res.body.user.should.include.keys(
          'id', 'email', 'createdAt', 'updatedAt'
        );               
        done();
      });
  });

  it('[GET /test/authorize] should return token-exchange in response headers', (done) => {
    authorizeHeaders.should.include.keys(
      'token-exchange'
    );
    done();
  });

  it('[GET /test/authorize] should support multitenancy', (done) => {
    authorizeBody.should.include.keys(
      'organization'
    );

    authorizeBody.user.should.include.keys(
      'organization_id'
    );

    authorizeBody.organization.should.include.keys(
      'id', 'name', 'createdAt', 'updatedAt'
    );
    done();
  });

  it('[GET /test/authorize] should not provide auth object with user password', (done) => {
    authorizeBody.user.should.not.include.keys(
      'password', 'passwordConfirmation'
    );
    done();
  });

  it('[GET /test/authorize] should not provide auth object with user perishableToken', (done) => {
    authorizeBody.user.should.not.include.keys(
      'perishableToken'
    );
    done();
  });

  it('[GET /test/authorize] should provide auth object with user having minimal attributes', (done) => {
    authorizeBody.user.should.include.keys(
      'id', 'email', 'createdAt', 'updatedAt'
    );
    done();
  });

});

describe('Password Change (MultiTenant)', function() {
  let loginBody = {};
  let loginHeaders = {};
  let authorizeBody = {};
  let authorizeHeaders = {};

  before((done) => {
    chai
      .request(app)
      .post('/auth/login')
      .send({ email: 'john@doe.com', password: 'testtest' })
      .end((err, res) => {
        loginBody = res.body;
        loginHeaders = res.headers;
        done();
      });
  });
  
  it('[POST /auth/password_change] should change password', (done) => {
    chai
      .request(app)
      .post('/auth/password_change')
      .set('Authorization', 'Bearer ' + loginBody.token)
      .send({ currentPassword: 'testtest', newPassword: 'testtest2' })
      .end((err, res) => {
        should.not.exist(err);
        res.should.have.status(200);
        res.should.be.json;
        res.body.should.be.a('object');
        res.body.should.include.keys(
          'success', 'message'
        );

        chai
          .request(app)
          .post('/auth/login')
          .send({ email: 'john@doe.com', password: 'testtest2' })
          .end((err, res) => {
            res.should.have.status(200);
            res.should.be.json;
            res.body.should.be.a('object');
            done();
          });
      });
  }).timeout(5000);

  it('[GET /auth/password_reset] should reset password', (done) => {
    chai
      .request(app)
      .get('/auth/password_reset?email=' + 'john@doe.com')
      .end((err, res) => {
        should.not.exist(err);
        res.should.have.status(200);
        res.should.be.json;
        res.body.should.be.a('object');
        res.body.should.include.keys(
          'success', 'message'
        );
        done();
      });
  }).timeout(5000);
  
  it('[GET /auth/password_reset_confirm] should confirm password reset', (done) => {
    r.table('users')
    .get(loginBody.user.id)
    .then((user) => {
      chai
        .request(app)
        .get('/auth/password_reset_confirm?token=' + user.perishableToken + '&email=john@doe.com')
        .end((err, res) => {
          should.not.exist(err);
          res.should.have.status(200);
          res.should.be.json;
          res.body.should.be.a('object');
          res.body.should.include.keys(
            'success', 'message'
          );
          done();
        });
    });    
  }).timeout(5000);

});

