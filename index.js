import express from 'express'
import { PORT as port, SECRET_KEY } from './config.js'
import jwt from 'jsonwebtoken'
import { UserRepo } from './user-repo.js'
import cookieParser from 'cookie-parser'

const app = express()
app.use(cookieParser())
app.use(express.json())
app.use(express.urlencoded({ extended: true }))

app.set('view engine', 'ejs')
app.use((req, res, next) => {
  const token = req.cookies.access_token
  req.session = { user: null }
  try {
    const data = jwt.verify(token, SECRET_KEY)
    req.session.user = data
  } catch {}
  next()
})

app.get('/', (req, res) => {
  res.render('index')
})

app.post('/login', async (req, res) => {
  const { username, password } = req.body
  try {
    const user = await UserRepo.login({ username, password })
    const token = jwt.sign({ id: user._id, user: user.username }, SECRET_KEY, { expiresIn: '1h' })
    res.cookie('access_token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 3600000
    }).send({
      message: 'login successful',
      user: { id: user._id, username: user.username },
      token
    })
  } catch (error) {
    res.status(401).send({ error: 'Credenciales incorrectas' })
  }
})
app.post('/register', async (req, res) => {
  const { username, password } = req.body
  console.log(username, password)
  try {
    const userId = await UserRepo.create({ username, password })
    res.send({ userId })
  } catch (error) {
    res.status(400).send({ error: error.message })
  }
})
app.post('/logout', (req, res) => {
  res.clearCookie('access_token')
  return res.redirect('/')
})

app.get('/protected', (req, res) => {
  const user = req.session.user
  res.render('protected', { user })
})

app.listen(port, () => {
  console.log(`Server running on port ${port}`)
})
