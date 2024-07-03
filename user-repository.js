import DBlocal from 'db-local'
import bcrypt from 'bcrypt'
import { SALT_ROUNDS } from './config.js'
const { Schema } = new DBlocal({ path: './db' })

const User = Schema('user', {
  _id: { type: String, required: true },
  username: { type: String, required: true },
  password: { type: String, required: true }
})
export class UserRepository {
  static async create ({ username, password }) {
    // 1. Validaciones de username (opcional: usar zod)
    Validation.username(username)
    Validation.password(password)

    // 2. Asegurarse que el username no existe
    const user = User.findOne({ username })
    if (user) throw new Error('username already exists')

    // 3. Crear el user
    const id = crypto.randomUUID()
    const passwordHash = await bcrypt.hash(password, SALT_ROUNDS) // hashSync <- bloquea el thread principal

    User.create({ _id: id, username, password: passwordHash }).save()
    return id
  }

  static login ({ username, password }) {
    Validation.username(username)
    Validation.password(password)

    const user = User.findOne({ username })
    if (!user) throw new Error('username not found')

    const isValid = bcrypt.compareSync(password, user.password)
    if (!isValid) throw new Error('password not match')

    const { password: _, ...publicUser } = user
    return publicUser
  }
}

class Validation {
  static username (username) {
    if (typeof username !== 'string') throw new Error('username must be a string')
    if (username.length < 3) throw new Error('username must be at least 3 characters')
  }

  static password (password) {
    if (typeof password !== 'string') throw new Error('password must be a string')
    if (password.length < 6) throw new Error('password must be at least 6 characters')
  }
}
