const express = require('express');
const router = express.Router();
const ExpressError = require('../expressError');
const db = require('../db');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const User = require('../models/user');
const { SECRET_KEY } = require('../config');

/** POST /login - login: {username, password} => {token}
 *
 * Make sure to update their last-login!
 *
 **/

router.post('/login', async (req, res, next) => {
    try{
        const {username, password} = req.body;
        const user =  await User.authenticate(username, password);
        const token = jwt.sign({username: user.username}, SECRET_KEY);
        await User.updateLoginTimestamp(user.username);
        req.user = user.username;
        return res.json({msg: `Welcome, ${user.username}`, token});
    } catch(e){
        return next(e);
    }
});


/** POST /register - register user: registers, logs in, and returns token.
 *
 * {username, password, first_name, last_name, phone} => {token}.
 *
 *  Make sure to update their last-login!
 */

router.post('/register', async(req, res, next) => {
    try{
        const {username, password, first_name, last_name, phone} = req.body;
        const user = await User.register(username, password, first_name, last_name, phone);
        return res.json(user);
    }catch(e){
        if(e.code === '23505'){
            return next(new ExpressError('Username already taken, please pick another!', 400));
        }
        return next(e);
    }
});

module.exports = router;