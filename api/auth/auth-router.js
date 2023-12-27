const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const { JWT_SECRET, BCRYPT_ROUNDS } = require("../secrets"); // use this secret!
const bcrypt = require("bcryptjs")
const jwt = require("jsonwebtoken")
const User = require("../users/users-model")

router.post("/register", validateRoleName, (req, res, next) => {
  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status 201
    {
      "user_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */
  let {username, password} = req.body
  const hash = bcrypt.hashSync(password, BCRYPT_ROUNDS)
  password = hash
  User.add({username: username, password: password, role_name: req.role_name})
    .then(data => {
      res.status(201).json({
        user_id: data.user_id,
        username: data.username,
        role_name: data.role_name
      })
    }).catch(next)
});


router.post("/login", checkUsernameExists, (req, res, next) => {
  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */
  let { username, password } = req.body
  if (bcrypt.compareSync(password, req.user.password)) {
    const token = buildToken(req.user)
    res.status(200).json({
      message: `${username} is back!`,
      token: token
    })
  } else {
    next({
      status: 401,
      message: "Invalid credentials"
    })
  }
})

function buildToken(user) {
  const payload = {
    subject: user.user_id,
    username: user.username,
    role_name: user.role_name,
  }
  const options = {
    expiresIn: "1d",
  }
  return jwt.sign(payload, `${JWT_SECRET}`, options)
}

module.exports = router;
