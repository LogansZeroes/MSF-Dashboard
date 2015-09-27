'use strict';
var router = require('express').Router();
module.exports = router;
var emailer = require('../../configure/email');

var mongoose = require('mongoose');
var Alert = mongoose.model('Alert');

var lastTime = 0;

router.post('/', function (req, res, next) {
    Alert.create({status: 'broken', email: req.body.email, temp: req.body.temp, time: req.body.time})
    .then( function (alert) {
        var currTime = new Date().getTime();
        //Don't want to send more than 1 email every 10 minutes
        if(currTime - lastTime > 600000) {
            lastTime = new Date().getTime();
            emailer.confirmEmail(alert);
        };
        res.status(201).json(alert);
    })
    .then( null, function (error) {
        console.log('alert error: ', error);
        next(error);
    });
});
