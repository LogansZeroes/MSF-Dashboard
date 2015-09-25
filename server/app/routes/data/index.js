'use strict';

var router = require('express').Router();
module.exports = router;
var https = require('https');

router.get('/', function (req, res) {
    https.get('https://dweet.io/get/latest/dweet/for/calm-patch', function(result) {
        var obj;
        result.on('data', function (response) {
            obj = response.toString();
        })
        result.on('end', function () {
            res.json(obj);
        })
    });
})
