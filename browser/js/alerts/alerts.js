app.config(function ($stateProvider) {
    $stateProvider.state('alerts', {
        url: '/alerts',
        templateUrl: 'js/alerts/alerts.html',
        controller: 'alertCtrl'
    })
})

app.controller('alertCtrl', function (DweetFactory, $scope, $state, $rootScope) {

    $scope.saveAlert = function (alert) {
        alert.upperBound = Number(alert.upperBound);
        alert.lowerBound = Number(alert.lowerBound);
        alert.temp;
        $rootScope.alert = alert;
        $rootScope.alertEntered = true;
        $state.go('home');
    }
})
