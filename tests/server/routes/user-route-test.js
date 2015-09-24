// Instantiate all models
var mongoose = require('mongoose');
require('../../../server/db/models');
var User = mongoose.model('User');

var expect = require('chai').expect;

var dbURI = 'mongodb://localhost:27017/testingDB';
var clearDB = require('mocha-mongoose')(dbURI);

var supertest = require('supertest');
var app = require('../../../server/app');

describe('Users Route', function () {

	beforeEach('Establish DB connection', function (done) {
		if (mongoose.connection.db) return done();
		mongoose.connect(dbURI, done);
	});

	afterEach('Clear test database', function (done) {
		clearDB(done);
	});

	describe('GET /api/users', function () {

		var agent;

		beforeEach('Create agent', function () {
			agent = supertest.agent(app);
		});

		beforeEach('Make a user', function (done) {
			User.create({email: "sean@sean.com", password: "mypass"})
			.then(function (user) {
				done();
			})
			.then(null, done);
		});

		it('should get return users with 200 response', function (done) {
			agent.get('/api/users/')
				.expect(200)
				.end(function (err, response) {
					if (err) return done(err);
					expect(response.body).to.be.an('array');
					expect(response.body).to.be.length(1);
					done();
				});
		});

		it('should not give back passwords', function (done) {
			agent.get('/api/users/')
				.expect(200)
				.end(function (err, response) {
					if (err) return done(err);
					expect(response.body.password).to.not.be.ok;
					done();
				});
		});

	});

	describe('POST /api/users', function () {

		var agent;

		beforeEach('Create agent', function () {
			agent = supertest.agent(app);
		});


		it('should make a user', function (done) {
			agent.post('/api/users/')
				.send({email: "sean@sean.com", password: "mypass"})
				.expect(201)
				.end(function (err, response) {
					if (err) return done(err);
					expect(response.body.email).to.equal('sean@sean.com');
					done();
				});
		});

		it('should not give back passwords', function (done) {
			agent.post('/api/users/')
				.send({email: "sean@sean.com", password: "mypass"})
				.expect(201)
				.end(function (err, response) {
					if (err) return done(err);
					expect(response.body.password).to.not.be.ok;
					done();
				});
		});

	});

	describe('GET /api/users/:userId', function () {

		var agent,
				userId;

		beforeEach('Create agent', function () {
			agent = supertest.agent(app);
		});

		beforeEach('Make a user', function (done) {
			User.create({email: "sean@sean.com", password: "mypass"})
			.then(function (user) {
				userId = user._id;
				done();
			})
			.then(null, done);
		});


		it('should get the user without password', function (done) {
			agent.get('/api/users/' + userId)
				.expect(200)
				.end(function (err, response) {
					if (err) return done(err);
					expect(response.body.email).to.equal('sean@sean.com');

					done()
				});
		});

	});

	describe('PUT /api/users/:userId', function () {

		var agent,
			userId,
			userId2,
			adminId;

		beforeEach('Create agent', function () {
			agent = supertest.agent(app);
		});

		beforeEach('Make a basic user', function (done) {
			User.create({email: "dude@dood.com", password: "dude"})
			.then(function (user) {
				userId2 = user._id;
				done();
			})
			.then(null, done);
		});

		beforeEach('Make a second basic user', function (done) {
			User.create({email: "sean@sean.com", password: "mypass"})
			.then(function (user) {
				userId = user._id;
				done();
			})
			.then(null, done);
		});

		beforeEach('Make an admin user', function (done) {
			User.create({email: "bean@bean.com", password: "mypass", isAdmin: true})
			.then(function (user) {
				adminId = user._id;
				done();
			})
			.then(null, done);
		});

		it('should err if not logged in', function (done) {
			agent.put('/api/users/' + userId)
				.send({email: "poop@poop.com"})
				.expect(401)
				.end(done);
		})

		it('should err if basic user tries to edit other user', function (done) {
			agent.post('/login')
				.send({email: "dude@dood.com", password: "dude"})
				.end(function (err, response) {
					agent.put('/api/users/' + userId)
						.send({email: "poop@poop.com"})
						.expect(403)
						.end(done);
				})
		});

		it('should edit own user when logged in', function (done) {
			agent.post('/login')
				.send({email: "sean@sean.com", password: "mypass"})
				.end(function (err, response) {
					agent.put('/api/users/' + userId)
						.send({email: "poop@poop.com"})
						.expect(201)
						.end(function (err, response) {
							if (err) return done(err);
							User.findById(userId)
							.then(function (user) {
								expect(user.email).to.equal('poop@poop.com');
								done();
							});
						});
				})

		});

		it('should edit other user when admin', function (done) {
			agent.post('/login')
				.send({email: "bean@bean.com", password: "mypass"})
				.end(function (err, response) {
					agent.put('/api/users/' + userId)
						.send({email: "poop@poop.com"})
						.expect(201)
						.end(function (err, response) {
							if (err) return done(err);
							User.findById(userId)
							.then(function (user) {
								expect(user.email).to.equal('poop@poop.com');
								done();
							});
						});
				})

		});


		it('should not give back passwords', function (done) {
			agent.post('/login')
				.send({email: "sean@sean.com", password: "mypass"})
				.end(function (err, response) {
					agent.put('/api/users/' + userId)
						.send({email: "poop@poop.com"})
						.expect(201)
						.end(function (err, response) {
							agent.put('/api/users/' + userId)
								.send({email: "poop@poop.com"})
								.expect(201)
								.end(function (err, response) {
									if (err) return done(err);
									expect(response.body.password).to.not.be.ok;
									done();
								});
						});
				})

		});

	});

});
