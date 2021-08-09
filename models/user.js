/** User class for message.ly */
const ExpressError = require('../expressError');
const db = require('../db');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const {BCRYPT_WORK_FACTOR, SECRET_KEY} = require('../config');

/** User of the site. */

class User {

  /** register new user -- returns
   *    {username, password, first_name, last_name, phone}
   */

  static async register(username, password, first_name, last_name, phone) {
    if(!username || !password || !first_name || !last_name || !phone){
      throw new ExpressError('Username, password, first and last name, and phone are required', 404);
    }

    const hashedPassword = await bcrypt.hash(password, BCRYPT_WORK_FACTOR);
    let date = new Date();
    const results = await db.query(
      `INSERT INTO users 
      (username, password, first_name, last_name, phone, join_at)
      VALUES ($1, $2, $3, $4, $5, $6) 
      RETURNING username, password, first_name, last_name, phone`, 
      [username, hashedPassword, first_name, last_name, phone, date.toLocaleString("en-US", {timeZone: "America/New_York"})]);
      
    return results.rows[0];
  }

  /** Authenticate: is this username/password valid? Returns boolean. */

  static async authenticate(username, password) {
      if(!username || !password){
        throw new ExpressError('Username and password required', 400);
      }

      const results = await db.query(`SELECT * FROM users WHERE username=$1`, [username]);
      const user = results.rows[0];
      if(user){
        if(await bcrypt.compare(password, user.password)){
          return user;
        }

        throw new ExpressError("Incorrect password", 404);
      }

      throw new ExpressError('Username not found', 404);
  }

  /** Update last_login_at for user */

  static async updateLoginTimestamp(username) {
    let date = new Date();

    const result = await db.query(`UPDATE users SET last_login_at = $1 WHERE username = $2`, 
      [date.toLocaleString("en-US", {timeZone: "America/New_York"}), username]);
  }

  /** All: basic info on all users:
   * [{username, first_name, last_name, phone}, ...] */

  static async all() {
    const users = await db.query(`SELECT username, first_name, last_name, phone FROM users`);
    return users.rows;
  }

  /** Get: get user by username
   *
   * returns {username,
   *          first_name,
   *          last_name,
   *          phone,
   *          join_at,
   *          last_login_at } */

  static async get(username) {
    const user = await db.query(
      `SELECT username, first_name, last_name, phone, join_at, last_login_at FROM users 
      WHERE username = $1`, [username]);

    if(!user.rows[0]){
      throw new ExpressError(`Can't find user: ${username}`, 404);
    }

    return user.rows[0];
  }

  /** Return messages from this user.
   *
   * [{id, to_user, body, sent_at, read_at}]
   *
   * where to_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesFrom(username) {
    const results = await db.query(
      `SELECT m.id, m.to_username, u.first_name, u.last_name, u.phone, m.body, m.sent_at, m.read_at FROM messages AS m
      JOIN users AS u ON m.to_username = u.username WHERE username=$1`, [username]);
    
    return results.rows.map(m => ({
      id: m.id,
      to_user: {
        username: m.to_username,
        first_name: m.first_name,
        last_name: m.last_name,
        phone: m.phone
      },
      body: m.body,
      sent_at: m.sent_at,
      read_at: m.read_at
    }));
  }

  /** Return messages to this user.
   *
   * [{id, from_user, body, sent_at, read_at}]
   *
   * where from_user is
   *   {id, first_name, last_name, phone}
   */

  static async messagesTo(username) {
    const results = await db.query(
      `SELECT m.id, m.from_username, u.first_name, u.last_name, u.phone, m.body, m.sent_at, m.read_at FROM messages AS m
      JOIN users AS u ON m.to_username = u.username WHERE username = $1`, [username]);
    
    return results.rows.map(m => ({
      id: m.id,
      from_user: {
        username: m.from_username,
        first_name: m.first_name,
        last_name: m.last_name,
        phone: m.phone
      },
      body: m.body,
      sent_at: m.sent_at,
      read_at: m.read_at
    }));
  }
}


module.exports = User;