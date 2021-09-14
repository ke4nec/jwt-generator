const jwt = require('jsonwebtoken')
const jwk = require('jwk-to-pem')
const fs = require('fs')
const uuid = require('uuid')
const process = require('process')

const args = process.argv.splice(2)

if (args.length === 0 || (args.length === 1 && args[0] === 'encode')) {
  generatorJwt()
} else if (args.length === 2 && args[0] === 'decode') {
  verifyJwt(args[1])
} else {
  console.log('node main.js encode\nnode main.js\nnode main.js decode jwt_string')
}

function generatorJwt() {

  try {
    const jwkContent = JSON.parse(fs.readFileSync('./jwk-pair.json'))
    const pem = jwk(jwkContent, {private: true})
    const userInfo = JSON.parse(fs.readFileSync('./user.json'))

    const payload = {
      name: userInfo.name,
      tenant: userInfo.tenant,
      scope: userInfo.scope,
      auth: userInfo.auth
    }

    jwt.sign(payload, pem, { jwtid: uuid.v4().split('-').join(''), algorithm: 'RS256', subject: userInfo.user, expiresIn: '29 days', notBefore: 0, header: { kid: jwkContent.kid, typ: "JWT", alg: "RS256" } }, (err, token) => {
      if (!err) {
        console.log(token);
      } else {
        console.error(err)
      }
    })
  } catch (error) {
    console.error(error)
  }
}


function verifyJwt(jwtString) {

  const jwkContent = JSON.parse(fs.readFileSync('./jwk-public.json'))
  const pem = jwk(jwkContent)
  
  jwt.verify(jwtString, pem, { complete: true }, (err, decoded) => {
    if (!err) {
      console.log(decoded)
    } else {
      console.error(err)
    }
  })

}

