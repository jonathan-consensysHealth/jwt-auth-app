require('dotenv').config()

const express = require('express')
const app = express()
const jwt = require('jsonwebtoken')
const { v4: uuidv4 } = require('uuid');

app.use(express.json())


// currently refreshTokens are just stored in memory, but need to cryptographically associate with user and store state in DB or redis 
let refreshTokens = []

// currently challenger are just stored in memory, but will need to cyrptograpically keep track of challengers and store in DB or redis 
let challenges = []


// create signed challenge to present to user for use in DID Auth 
app.post('/didAuthChallengeRequest', (req, res) => {
  // create random nouce ideally using uuid 

  const randomUUID = uuidv4()
  const nounce = { nounce: randomUUID , callback: "/login" }  
  // will need additional information more than nouce for user to validate including DID in order for user to validate the signature 
  const challenge = jwt.sign(nounce, process.env.REFRESH_TOKEN_SECRET)
  challenges.push(challenge)
  res.json({ didChallenge: challenge })

})


// rather than login with user name and password,
// parse jwt, use did-jwt to fetch public key from infura, validate the nounce, 
// if valid then store state in shared server side infrastructure regarding TTL 
app.post('/login', (req, res) => {
  // Authenticate User using DID auth 
  
  const username = req.body.username
  const user = { name: username }

  // need to decode the base64 jwt
  // extract the bode of the payload 
  // verifiy that the challenge nounce is in the set of challengers 
  // valiidate the signature of the JWT presented from the user including fetch the DID document and validate signature of jwt presented
  // only then `login` the user and create typical access and refresh tokens and store in mimic db above 

  // generate an Access Token for the User derived from the stored TOKEN secret in .env 
  const accessToken = generateAccessToken(user)
  const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET)
  refreshTokens.push(refreshToken)
  res.json({ accessToken: accessToken, refreshToken: refreshToken })
})




// mimics the request for an update token with use of refresh token 
app.post('/refreshToken', (req, res) => {
  const refreshToken = req.body.token
  if (refreshToken == null) return res.sendStatus(401)
  if (!refreshTokens.includes(refreshToken)) return res.sendStatus(403)
  jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403)
    const accessToken = generateAccessToken({ name: user.name })
    res.json({ accessToken: accessToken })
  })
})



// mimics logout, requires user to have a valid access token 
app.delete('/logout', (req, res) => {
  refreshTokens = refreshTokens.filter(token => token !== req.body.token)
  res.sendStatus(204)
})

// helper functions 

// create a new accessToken for given user 
function generateAccessToken(user) {
  return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '60s' })
}


app.listen(4000)