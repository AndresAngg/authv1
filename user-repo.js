import DBLocal from 'db-local'
import crypto from 'crypto'
import bcrypt from 'bcrypt'
import { SALT_ROUNDS } from './config.js'

const { Schema } = new DBLocal({ path: './database' })

const User = Schema('User', {
  _id: { type: String, primary: true },
  username: { type: String, required: true },
  password: { type: String, required: true }

})
export class UserRepo {
  static async create ({ username, password }) {
    Validation.validateUsername(username)
    Validation.validatePassword(password)

    const user = User.findOne({ username })
    if (user) throw new Error('username already exists')

    const id = crypto.randomUUID()
    const hashPassword = await bcrypt.hash(password, SALT_ROUNDS)

    User.create({ _id: id, username, password: hashPassword }).save()
    return id
  }

  static async login ({ username, password }) {
    Validation.validateUsername(username)
    Validation.validatePassword(password)

    const user = User.findOne({ username })
    if (!user) throw new Error('no exists user with this username')

    const isValidPassoword = await bcrypt.compare(password, user.password)
    if (!isValidPassoword) throw new Error('invalid password')
    return user
  }
}
class Validation {
  static validateUsername (username) {
    if (!username) throw new Error('username is required')
    if (typeof username !== 'string') throw new Error('username must be a string')
    if (username.length < 3) throw new Error('username must be at least 3 characters long')
  }

  static validatePassword (password) {
    if (!password) throw new Error('password is required')
    if (typeof password !== 'string') throw new Error('password must be a string')
    if (password.length < 6) throw new Error('password must be at least 6 characters long')
  }
}
