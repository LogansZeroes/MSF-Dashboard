var dbURI = 'mongodb://localhost:27017/testingDB';
var clearDB = require('mocha-mongoose')(dbURI);

var sinon = require('sinon');
var expect = require('chai').expect;
var mongoose = require('mongoose');

// Require in all models.
require('../../../server/db/models');

var Order = mongoose.model('Order');
var User = mongoose.model('User');
var Product = mongoose.model('Product');
var Category = mongoose.model('Category');
var Store = mongoose.model('Store')



describe('Order model', function () {

	var createUser = function () {
		return User.create({ email: 'obama@gmail.com', password: 'potus' });
	};

	var createCategory = function () {
		return Category.create({title: 'Misc'});
	};

	beforeEach('Establish DB connection', function (done) {
		if (mongoose.connection.db) return done();
		mongoose.connect(dbURI, done);
	});

	var productId,
		product,
		categoryId,
		userId,
		storeId;

	beforeEach('Create user, store, category, product', function (done) {
		User.create({email: "bowser@mariobros.com"})
		.then(function(user){
			userId = user._id;
			return Store.create({
				name: "Princess Peach Kidnapping Tools",
				urlName: "peach",
				user: userId
			})
		})
		.then(function(store){
			storeId = store._id;
			return Category.create({
				title: 'Extreme Watersports'
			})
		})
		.then(function (category) {
			categoryId = category._id;
		})
		.then(function (){
			return Product.create({
				name: 'surfboard',
				categories: [categoryId],
				price: 56,
				store: storeId
			})
		})
		.then(function (foundProduct) {
			productId = foundProduct._id;
			product = foundProduct
			done();
		});
	});

	afterEach('Clear test database', function (done) {
		clearDB(done);
	});

	it('should exist', function () {
		expect(Order).to.be.a('function');
	});

	describe('Validations', function () {

		it('should err without session', function (done) {
			Order.create({items: [{quantity: 0, product: productId}]})
			.then(null, function (error){
				expect(error.errors.session).to.exist;
				expect(error.errors.items).to.not.exist;
				done();
			})
		})

		it('should err without items', function (done) {
			Order.create({session: 'fakeSessionThing'})
			.then(null, function (error) {
				expect(error.errors.items).to.exist;
				done();
			})
		})

		it('should err with items without quantity, product', function (done) {
			Order.create({
				user: userId,
				items: [{}]
			})
			.then(function(order){
				done();
			})
			.then(null, function (error) {
				expect(error.errors['items.0.product']).to.exist;
				expect(error.errors['items.0.quantity']).to.exist;
				done();
			})
		})
	})
});
