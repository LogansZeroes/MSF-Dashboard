'use strict';
var router = require('express').Router();
module.exports = router;

router.use('/users', require('./users'));

router.use('/alerts', require('./alerts'));

router.use('/data', require('./data'));


router.use(function (req, res) {
    res.status(404).end();
});
