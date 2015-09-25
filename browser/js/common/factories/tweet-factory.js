app.factory('TweetFactory', function ($http) {
    var Tweets = function(props) {
        angular.extend(this, props);
    };

    Tweets.getAll = function (){
		// return $http.jsonp('https://dweet.io/listen/for/dweets/from/calm-patch')
        // return $http.get('https://dweet.io/get/latest/dweet/for/calm-patch')
		// .success(function(response){
        //     console.log(response);
		// 	return response.data;
		// });
        return $http.get('/api/data')
        .then(function (response){
            return response.data;
        })
	};

    return Tweets;

    // return {
    //     getAll: $.getJSON("https://dweet.io/get/latest/dweet/for/calm-patch", function(data) {
    //         console.log(data);
    //         return data;
    //     })
    // }
})
