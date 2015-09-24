app.config(function($stateProvider){
	$stateProvider.state('users', {
		url: '/users',
		templateUrl: '/js/users/users.html',
		resolve:{
			users: function(UserFactory){
				return UserFactory.getAll();
			}
		},
		controller: function ($scope, users, Session, $state) {
			$scope.users = users;
			if (!Session.user || !Session.user.isAdmin){
				$state.go('home');
			}
		}
});
});
