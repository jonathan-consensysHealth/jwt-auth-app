require('dotenv').config()

const express = require('express')
const app = express()
const jwt = require('jsonwebtoken')

app.use(express.json())  // simple express JSON REST API 


// example resource that is protected by AuthServer.js 
// in real world this would be database request 
const resources = [
  {
    username: 'Alice',
    data: 'Example data for Alice'
  },
  {
    username: 'Bob',
    data: 'Example data for Bob'
  }
]


// filter mimics authorization workflow of limiting what the use is allowed to perform 
// based on the request user name sent in get and the 'db' in reource above 
app.get('/resource', authenticateToken, (req, res) => {  
  res.json(resources.filter(post => post.username === req.user.name))
})




// authentication of Token prior to serving resource
// in real world this would be comparing token in database.   
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization']
  const token = authHeader && authHeader.split(' ')[1]
  if (token == null) return res.sendStatus(401)

  // use jwt library to validate the token included in header 
  // future state, use did-jwt to authenticate the user 
  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    console.log(err)
    if (err) return res.sendStatus(403)
    req.user = user
    next()
  })
}

app.listen(3000)