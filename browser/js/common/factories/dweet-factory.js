app.factory('DweetFactory', function ($http) {
    var Dweets = function(props) {
        angular.extend(this, props);
    };

    Dweets.getAll = function (){
        return $http.get('/api/data')
        .then(function (response){
            return response.data;
        })
	};

    Dweets.getLatest = function () {
        return $http.get('/api/data/latest')
        .then (function (response) {
            return response.data;
        })
    };

    return Dweets;
})
