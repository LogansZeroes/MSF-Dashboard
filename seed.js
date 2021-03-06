/*

This seed file is only a placeholder. It should be expanded and altered
to fit the development of your application.

It uses the same file the server uses to establish
the database connection:
--- server/db/index.js

The name of the database used is set in your environment files:
--- server/env/*

This seed file has a safety check to see if you already have users
in the database. If you are developing multiple applications with the
fsg scaffolding, keep in mind that fsg always uses the same database
name in the environment files.

*/

var mongoose = require('mongoose');
var Promise = require('bluebird');
var chalk = require('chalk');
var connectToDb = require('./server/db');
var User = mongoose.model('User');


var seedUsers = function () {

    var users = [{
        email: 'testing@fsa.com',
        firstName: 'Full',
        lastName: 'Stack',
        password: 'password'
    }, {
        email: 'obama@gmail.com',
        firstName: 'Barack',
        lastName: 'Obama',
        password: 'potus'
    }, {
        email: 'd@d.com',
        firstName: 'Jimin',
        lastName: 'Admin',
        password: 'd',
        isAdmin: true
    }];

    return Promise.resolve(User.create(users));
};

connectToDb.then(function () {
    return Promise.resolve(User.find().exec())
    .then(function (users) {
        if (users.length === 0) {
            return seedUsers();
        } else {
            console.log(chalk.magenta('Seems to already be user data, exiting!'));
            process.kill(0);
        }
    }).then(function () {
        console.log(chalk.green('Seed successful!'));
        process.kill(0);
    }).catch(function (err) {
        console.dir(err);
        process.kill(1);
    });
});
