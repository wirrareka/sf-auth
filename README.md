# Chaos Authorization Library

Performs all basic authentication tasks, provides organization => users hierarchy and simple express app integration

## Usage

```
const r = require('rethinkdbdash')({ db: 'chaos' });

const settings = {
  secret: 'MY_SUPER_DUPER_SECRET_HASH',
  site: {
    name: 'Some Cool Site',
    url: 'http://localhost:3000'
  },
  email: {
    from: "no-reply@foo.com",
    host: "mail.somewhere.com",
    user: "username@somewhere.com",
    password: "foobar",
    ssl: true
  }
};

const auth = require('chaos-auth')(r, settings);

const app = express();
app.use(cors());
app.use(bodyParser.json())
   .use(bodyParser.urlencoded({ extended: false }));

app.use('/auth', auth.router);
app.get('/test', auth.authorize, (req, res) => {  
  res.send({ success: true, message: 'i am authorized' });
});
```

## Available Middleware

### authorize
authorizes JWT token, builds Authorization Object under req.auth

```
app.get('/custom_endpoint', auth.authorize, (req, res) => {
  // available only for authorized requests
  console.log('logged in with token', req.auth.token);
  res.send({
    user: req.auth.user,
    organization: req.auth.organization
  })
});
```

### requireSuperuser
```
app.get('/custom_endpoint', auth.authorize, auth.requireSuperuser, (req, res) => {
  // available only for superuser
});
```

### requireAdmin
```
app.get('/custom_endpoint', auth.authorize, auth.requireAdmin, (req, res) => {
  // available only for admin
});
```

## Available REST endpoints

### POST /register
registers user account and sends confirmation email, until user confirms the account the user has 

```
{
  "user": { 
		"email": "foo@bar.com",
		"password": "foobar",
		"passwordConfirmation": "foobar",
		"firstName": "John",
		"lastName": "Doe"
	},
	"organization": {
		"name": "Foobar ltd",
		"email": "info@bar.com",
		"country": "Finland"
	}
}
```
you can add your own attributes as long as it's not "id", "createdAt", "updatedAt", "perishableToken"

### GET /activate?token=TOKEN&redirect_to=SOMEWHERE
activates the account using perishable token, then redirects to supplied link

### POST /login
creates a session and returns Authorization Object with User, Organization and Token
```
{
  "email": "foo@bar.com",
  "password": "foobar"
}
```

### POST /admin/login [JWT] [ADMIN]
creates a session using different organization
```
{
  "organization_id": "abcdefgh"
}
```

### GET /logout [JWT]
deletes the current token

### GET /password_reset
sets perishable token and sends password request confirmation email

### GET /password_reset_confirmation?token=TOKEN&redirect_to=SOMEWHERE
generates random password, sends email to user and redirects to provided link, uses perishable token

### POST /password_change [JWT]
changes password of user
```
{
  "currentPassword": "foobar",
  "newPassword": "foobar2"
}
```

### GET / [JWT]
returns Authorization Object with User, Organization and Token for current session

### POST /users [JWT] [SUPERUSER]
allows superuser to create other users under the same organization

```
{ 
  "email": "foo@bar.com",
  "password": "foobar",
  "passwordConfirmation": "foobar",
  "firstName": "John",
  "lastName": "Doe"
}
```

### PUT /users/:id [JWT] [SUPERUSER]
allows superuser to modify other users under the same organization

```
{ 
  "email": "foo@bar.com",
  "password": "foobar",
  "passwordConfirmation": "foobar",
  "firstName": "John",
  "lastName": "Doe"
}
```

## Template customization
you can use your own email templates and mail subjects by setting following properties in *settings* objects
templates are standard handlebar templates using {{ variable }} style. Check builtin templates for available properties.

```
var fs = require('fs');

var settings = {
  emails: {
    confirm: {
      subject: "Confirm your email!",
      template: fs.readFileSync('./templates/confirm.html')
    }
  }
}
```

# Testing

Tests will run their own express api server using this library. Email sending tests are not yet implemented.

```
  npm run test
```