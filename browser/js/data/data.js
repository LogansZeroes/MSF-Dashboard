app.config(function ($stateProvider) {
    $stateProvider
    .state('data', {
        url: '/data',
        templateUrl: 'js/data/data.html',
        controller: function ($scope, allDweets) {
          $scope.dweets = allDweets;
        },
        resolve: {
            // findDweets: function (DweetFactory) {
            //     return DweetFactory.getAll();
            // };
            allDweets: function (DweetFactory) {
                return DweetFactory.getAll();
            }
        }
    })
});
