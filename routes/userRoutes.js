const Router = require('express').Router()
const userCtrl = require('../controllers/userController')

// Middleware Imports
const adminAuth = require('../middleware/auth')

Router.post(`/register`, userCtrl.register)

Router.post('/login', userCtrl.login)

Router.post('/refresh_token', userCtrl.getAccessToken)

Router.get('/logout', userCtrl.logout)

Router.get('/auth_example', adminAuth, userCtrl.authExample)


module.exports = Router