'use strict';

var router = require('express').Router();
module.exports = router;
// var https = require('https');
var dweetClient = require("node-dweetio");
var dweetio = new dweetClient();
var Dweet = require('mongoose').model('Dweet');

router.get('/latest', function (req, res) {
    var currDate = new Date();
    var hourBack = new Date(currDate.getTime() - 60*60*1000);

    dweetio.get_latest_dweet_for("calm-patch", function(err, latestDweet){

        var dweet = latestDweet[0]; // Dweet is always an array of 1

        var obj = {
            name: dweet.thing,
            created: dweet.created,
            temp: dweet.content.Temperature
        };

        Dweet.create(obj);

        //Remove all dweets prior to the last hour (for garbage collection)
        Dweet.find({created: {$lte: hourBack} }).remove().exec();
        // console.log('The Name ', dweet.thing); // The generated name
        // console.log('The Content ', dweet.content); // The content of the dweet
        // console.log(dweet.created); // The create date of the dweet
        res.json(dweet);
    });
})

router.get('/', function (req, res) {
    // dweetio.listen_for("calm-patch", function(dweet) {
    //     console.log(dweet);
    //     // broadcast with rootscope??
    // })
    dweetio.get_all_dweets_for('calm-patch', function(err, dweets) {
        res.json(dweets);
    })
})
