app.config(function ($stateProvider) {
    $stateProvider.state('alerts', {
        url: '/alerts',
        templateUrl: 'js/alerts/alerts.html',
        controller: 'alertCtrl'
    })
})

app.controller('alertCtrl', function (DweetFactory, $scope, $state) {
    $scope.sendAlert = function (alert) {
        DweetFactory.postAlert(alert)
        .then (function (postedAlert) {
            $state.go('home');
        })
    }
})
