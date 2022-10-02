require('dotenv').config()
const express = require('express')
const mongoose = require('mongoose')
const cors = require('cors')
const cookieParser = require('cookie-parser')
const fileUpload = require('express-fileupload')

const app = express()
app.use(express.json())
app.use(cors())
app.use(cookieParser())
app.use(fileUpload({
    useTempFiles: true
}))

const service = 'auth'
const version = 'v1'

// Routes
app.use(`/${service}/${version}`,require('./routes/userRoutes'))

// connect to mongoDB
const URI = process.env.MONGODB_URL
mongoose.connect(URI,{
    useUnifiedTopology: true
}, err => {
    if(err) throw err;
    console.log("Connected to mongoDB successfully")
})

const PORT = process.env.PORT || 5000
app.listen(PORT, () => {
    console.log('server is running on port', PORT)
})