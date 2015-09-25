'use strict';
var router = require('express').Router();
module.exports = router;
var _ = require('lodash');

var User = require('mongoose').model('User');


router.get('/', function (req, res) {
	User.find()
	.then(function (users) {
		users = users.map(function (user) {
			return _.omit(user.toJSON(), ['salt', 'password']);
		});
		res.json(users);
	});
});

router.post('/', function (req, res) {
	delete req.body.isAdmin;
	User.create(req.body)
	.then(function (user) {
		res.status(201).json(_.omit(user.toJSON(), ['salt', 'password']));
	});
});

router.put('/:userId', function (req, res, next) {
	if(!req.user) {
		var err = new Error('Not logged in')
		err.status = 401;
		return next(err);
	}
	if(req.user._id.toString() !== req.params.userId && !req.user.isAdmin) {
		console.log('says not same user')
		err = new Error('You can\'t edit someone else\'s page')
		err.status = 403;
		return next(err);
	}
	req.foundUser = _.assign(req.foundUser, req.body);
	req.foundUser.save()
	.then(function (editedUser) {
		res.status(201).json(_.omit(editedUser.toJSON(), ['salt', 'password']));
	});
});

router.get('/:userId', function (req, res) {
	res.json(_.omit(req.foundUser.toJSON(), ['salt', 'password']));
});

router.delete('/:userId', function (req, res, next){
	if (!req.user){
		res.status(401).end();
	}
	if (!req.user.isAdmin) {
		res.status(403).end();
	}

	req.foundUser.remove() //remove user
	.then(function(){
		res.status(204).end();
	})
    .then(null, next);
});

router.param('userId', function (req, res, next, userId) {
	User.findById(userId)
	.then(function (user) {
		req.foundUser = user;
		next();
	})
	.then(null, next);
});
