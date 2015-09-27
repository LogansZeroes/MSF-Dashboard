'use strict';
var router = require('express').Router();
module.exports = router;
var emailer = require('../../configure/email');

var mongoose = require('mongoose');
var Alert = mongoose.model('Alert');

router.post('/', function (req, res, next) {
    var currDate = new Date();
    var currTime = currDate.toString().slice(16);
    Alert.create({status: 'broken', email: req.body.email, time: currTime})
    .then( function (alert) {
        emailer.confirmEmail(alert);
        res.status(201).json(alert);
    })
    .then( null, function (error) {
        console.log('alert error: ', error);
        next(error);
    });
});
