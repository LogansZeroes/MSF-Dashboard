app.directive('userDetail', function(UserFactory, $stateParams, $state, Session){
  return {
	restrict: 'E',
	templateUrl: '/js/common/directives/user/user-detail/user-detail.html',
	link: function (scope){
		scope.isDetail = true;
		scope.isAdmin = Session.user.isAdmin;
		scope.editMode = false;
        scope.editPass = false;

        //FIX THIS LINE
        if (scope.user = Session.user) scope.isOwner = true

		scope.enableEdit = function () {
			scope.cached = angular.copy(scope.user);
			scope.editMode = true;
		};
		scope.cancelEdit = function(){
			scope.user = angular.copy(scope.cached);
			scope.editMode = false;
            scope.editPass= false;
		};
		scope.saveUser = function (user) {
			UserFactory.edit(user._id, user)
			.then(function (updatedUser) {
				scope.user = updatedUser;
				scope.editMode = false;
                scope.editPass= false;
			});
		};
		scope.deleteUser = function(user){
			UserFactory.delete(user)
			.then(function(){
				scope.editMode = false;
                scope.editPass= false;
				$state.go('home');
			});
		};

        scope.passwordEdit = function(){
            // UserFactory.edit(id, {'newPass': true})
            // .then(function () {
            //     // scope.newPass = true;
            //     scope.editMode = false;
            // });
            scope.cached = angular.copy(scope.user);
            scope.editPass = true;
        };
	},
	scope: {
		user: "="
	}
  };
});
