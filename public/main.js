'use strict';
window.app = angular.module('MSFTemp', ['ui.router', 'ui.bootstrap', 'fsaPreBuilt']);

app.config(function ($urlRouterProvider, $locationProvider) {

    // this makes the '/users/' route correctly redirect to '/users'
    $urlRouterProvider.rule(function ($injector, $location) {

        var re = /(.+)(\/+)(\?.*)?$/;
        var path = $location.url();

        if (re.test(path)) {
            return path.replace(re, '$1$3');
        }

        return false;
    });
    // This turns off hashbang urls (/#about) and changes it to something normal (/about)
    $locationProvider.html5Mode(true);
    $urlRouterProvider.when('/auth/:provider', function () {
        window.location.reload();
    });
    // If we go to a URL that ui-router doesn't have registered, go to the "/" url.
    $urlRouterProvider.otherwise('/');
});

// This app.run is for controlling access to specific states.
app.run(function ($rootScope, AuthService, $state) {

    // The given state requires an authenticated user.
    var destinationStateRequiresAuth = function destinationStateRequiresAuth(state) {
        return state.data && state.data.authenticate;
    };

    // $stateChangeStart is an event fired
    // whenever the process of changing a state begins.
    $rootScope.$on('$stateChangeStart', function (event, toState, toParams) {

        if (!destinationStateRequiresAuth(toState)) {
            // The destination state does not require authentication
            // Short circuit with return.
            return;
        }

        if (AuthService.isAuthenticated()) {
            // The user is authenticated.
            // Short circuit with return.
            return;
        }

        // Cancel navigating to new state.
        event.preventDefault();

        AuthService.getLoggedInUser().then(function (user) {
            // If a user is retrieved, then renavigate to the destination
            // (the second time, AuthService.isAuthenticated() will work)
            // otherwise, if no user is logged in, go to "login" state.
            if (user) {
                $state.go(toState.name, toParams);
            } else {
                $state.go('login');
            }
        });
    });
});

app.config(function ($stateProvider) {
    $stateProvider.state('alerts', {
        url: '/alerts',
        templateUrl: 'js/alerts/alerts.html',
        controller: 'alertCtrl'
    });
});

app.controller('alertCtrl', function (DweetFactory, $scope, $state, $rootScope) {

    $scope.saveAlert = function (alert) {
        alert.upperBound = Number(alert.upperBound);
        alert.lowerBound = Number(alert.lowerBound);
        alert.temp;
        $rootScope.alert = alert;
        $rootScope.alertEntered = true;
        $state.go('home');
    };
});

app.config(function ($stateProvider) {
    $stateProvider.state('data', {
        url: '/data',
        templateUrl: 'js/data/data.html',
        controller: function controller($scope, allDweets) {
            $scope.dweets = allDweets;
        },
        resolve: {
            // findDweets: function (DweetFactory) {
            //     return DweetFactory.getAll();
            // };
            allDweets: function allDweets(DweetFactory) {
                return DweetFactory.getAll();
            }
        }
    });
});

app.config(function ($stateProvider) {
    $stateProvider.state('docs', {
        url: '/docs',
        templateUrl: 'js/docs/docs.html'
    });
});

(function () {

    'use strict';

    // Hope you didn't forget Angular! Duh-doy.
    if (!window.angular) throw new Error('I can\'t find Angular!');

    var app = angular.module('fsaPreBuilt', []);

    app.factory('Socket', function () {
        if (!window.io) throw new Error('socket.io not found!');
        return window.io(window.location.origin);
    });

    // AUTH_EVENTS is used throughout our app to
    // broadcast and listen from and to the $rootScope
    // for important events about authentication flow.
    app.constant('AUTH_EVENTS', {
        loginSuccess: 'auth-login-success',
        loginFailed: 'auth-login-failed',
        signupSuccess: 'auth-signup-success',
        signupFailed: 'auth-signup-failed',
        logoutSuccess: 'auth-logout-success',
        sessionTimeout: 'auth-session-timeout',
        notAuthenticated: 'auth-not-authenticated',
        notAuthorized: 'auth-not-authorized'
    });

    app.factory('AuthInterceptor', function ($rootScope, $q, AUTH_EVENTS) {
        var statusDict = {
            401: AUTH_EVENTS.notAuthenticated,
            403: AUTH_EVENTS.notAuthorized,
            419: AUTH_EVENTS.sessionTimeout,
            440: AUTH_EVENTS.sessionTimeout
        };
        return {
            responseError: function responseError(response) {
                $rootScope.$broadcast(statusDict[response.status], response);
                return $q.reject(response);
            }
        };
    });

    app.config(function ($httpProvider) {
        $httpProvider.interceptors.push(['$injector', function ($injector) {
            return $injector.get('AuthInterceptor');
        }]);
    });

    app.service('AuthService', function ($http, Session, $rootScope, AUTH_EVENTS, $q) {

        function onSuccessfulLogin(response) {
            var data = response.data;
            Session.create(data.id, data.user);
            $rootScope.$broadcast(AUTH_EVENTS.loginSuccess);
            return data.user;
        }

        //add successful signup
        function onSuccessfulSignup(response) {
            var data = response.data;
            Session.create(data.id, data.user);
            $rootScope.$broadcast(AUTH_EVENTS.signupSuccess);
            return data.user;
        }

        // Uses the session factory to see if an
        // authenticated user is currently registered.
        this.isAuthenticated = function () {
            return !!Session.user;
        };

        this.getLoggedInUser = function (fromServer) {

            // If an authenticated session exists, we
            // return the user attached to that session
            // with a promise. This ensures that we can
            // always interface with this method asynchronously.

            // Optionally, if true is given as the fromServer parameter,
            // then this cached value will not be used.

            if (this.isAuthenticated() && fromServer !== true) {
                return $q.when(Session.user);
            }

            // Make request GET /session.
            // If it returns a user, call onSuccessfulLogin with the response.
            // If it returns a 401 response, we catch it and instead resolve to null.
            return $http.get('/session').then(onSuccessfulLogin)['catch'](function () {
                return null;
            });
        };

        this.login = function (credentials) {
            return $http.post('/login', credentials).then(onSuccessfulLogin)['catch'](function () {
                return $q.reject({ message: 'Invalid login credentials.' });
            });
        };

        this.logout = function () {
            return $http.get('/logout').then(function () {
                Session.destroy();
                $rootScope.$broadcast(AUTH_EVENTS.logoutSuccess);
            });
        };

        this.signup = function (credentials) {
            return $http.post('/signup', credentials).then(onSuccessfulSignup);
        };
    });

    app.service('Session', function ($rootScope, AUTH_EVENTS) {

        var self = this;

        $rootScope.$on(AUTH_EVENTS.notAuthenticated, function () {
            self.destroy();
        });

        $rootScope.$on(AUTH_EVENTS.sessionTimeout, function () {
            self.destroy();
        });

        this.id = null;
        this.user = null;

        this.create = function (sessionId, user) {
            this.id = sessionId;
            this.user = user;
        };

        this.destroy = function () {
            this.id = null;
            this.user = null;
        };
    });
})();

app.config(function ($stateProvider) {
    $stateProvider.state('home', {
        url: '/',
        templateUrl: 'js/home/home.html',
        controller: function controller($scope, DweetFactory, latestTemp, $rootScope) {
            //Create array of latest dweets to display on home state
            $scope.homeDweets = [];
            $rootScope.homeAlerts = [];

            $scope.error = null;

            //Initialize with first dweet
            DweetFactory.getLatest().then(function (dweet) {
                $scope.prevDweet = dweet;
            });

            // console.log($rootScope.alert)

            var line1 = new TimeSeries();
            var line2 = new TimeSeries();

            // Check every half second to see if the last dweet is new, then push to homeDweets, then plot
            if ($rootScope.alert) {
                setInterval(function () {
                    DweetFactory.getLatest().then(function (dweet) {
                        $scope.lastDweet = dweet;
                    }).then(function () {
                        var randomTemp = Math.random() * 5 + 70;
                        if ($scope.prevDweet.created != $scope.lastDweet.created) {
                            $scope.homeDweets.push($scope.lastDweet);
                            $scope.prevDweet = $scope.lastDweet;
                            line1.append(new Date().getTime(), $scope.lastDweet.content['Temperature']);
                            //Random plot to check that the graph is working
                            line2.append(new Date().getTime(), randomTemp);
                        }
                        //Detect if the temperature breaks out of safe range
                        if ($scope.lastDweet.content['Temperature'] > $rootScope.alert.upperBound || $scope.lastDweet.content['Temperature'] < $rootScope.alert.lowerBound) {
                            console.log('break in cold chain');
                            var currDate = new Date();
                            var currTime = currDate.toString().slice(16);
                            $rootScope.alert.time = currTime;
                            $rootScope.alert.temp = $scope.lastDweet.content['Temperature'];
                            DweetFactory.postAlert($rootScope.alert).then(function (postedAlert) {
                                $rootScope.homeAlerts.push(postedAlert);
                                $scope.error = 'Break in cold chain detected!!';
                            });
                        }
                        //Detect if the temperature breaks out of safe range
                        //TURN ON TO DEMONSTRATE BREAK IN COLD CHAIN ALERT & EMAIL FEATURE
                        if (randomTemp > $rootScope.alert.upperBound || randomTemp < $rootScope.alert.lowerBound) {
                            console.log('break in cold chain 2');
                            var currDate = new Date();
                            var currTime = currDate.toString().slice(16);
                            $rootScope.alert.time = currTime;
                            $rootScope.alert.temp = randomTemp;
                            DweetFactory.postAlert($rootScope.alert).then(function (postedAlert) {
                                $rootScope.homeAlerts.push(postedAlert);
                                $scope.error = 'Break in cold chain detected!!';
                            });
                        }

                        while ($scope.homeDweets.length > 100) {
                            $scope.homeDweets.shift();
                        }
                        while ($scope.homeAlerts.length > 100) {
                            $scope.homeAlerts.shift();
                        }
                    });
                }, 500);
            }

            //Make a smoothie chart with aesthetically pleasing properties
            var smoothie = new SmoothieChart({
                grid: {
                    strokeStyle: 'rgb(63, 160, 182)',
                    fillStyle: 'rgb(4, 5, 91)',
                    lineWidth: 1,
                    millisPerLine: 500,
                    verticalSections: 4
                },
                maxValue: $rootScope.alert.upperBound * 1.003,
                minValue: $rootScope.alert.lowerBound * 0.997,
                // maxValueScale: 1.01,
                // minValueScale: 1.02,
                timestampFormatter: SmoothieChart.timeFormatter,
                //The range of acceptable temperatures visualized
                //Should change 'value' accordingly
                horizontalLines: [{
                    color: '#880000',
                    lineWidth: 5,
                    value: $rootScope.alert.upperBound || 70
                }, {
                    color: '#880000',
                    lineWidth: 5,
                    value: $rootScope.alert.lowerBound || 68
                }]
            });

            smoothie.addTimeSeries(line1, {
                strokeStyle: 'rgb(0, 255, 0)',
                fillStyle: 'rgba(0, 255, 0, 0.4)',
                lineWidth: 3
            });
            smoothie.addTimeSeries(line2, {
                strokeStyle: 'rgb(255, 0, 255)',
                fillStyle: 'rgba(255, 0, 255, 0.3)',
                lineWidth: 3
            });

            smoothie.streamTo(document.getElementById("chart"), 300);
        },
        resolve: {
            latestTemp: function latestTemp(DweetFactory) {
                return DweetFactory.getLatest().then(function (dweet) {
                    return dweet.content['Temperature'];
                });
            }
        }
    });
});

app.config(function ($stateProvider) {
    $stateProvider.state('latest', {
        url: '/data/latest',
        templateUrl: 'js/latest/latest.html',
        controller: function controller($scope, latestDweet) {
            $scope.latestDweet = latestDweet;
        },
        resolve: {
            latestDweet: function latestDweet(DweetFactory) {
                return DweetFactory.getLatest();
            }
        }
    });
});

app.config(function ($stateProvider) {
    $stateProvider.state('resetPass', {
        url: '/reset/:userId',
        templateUrl: 'js/resetPass/resetPass.html',
        controller: 'ResetCtrl'
    });
});

app.controller('ResetCtrl', function ($scope, UserFactory, $stateParams, AuthService, $state) {

    $scope.resetPass = function (newPass) {
        UserFactory.edit($stateParams.userId, { 'newPass': false, 'password': newPass }).then(function (user) {
            AuthService.login({ email: user.email, password: newPass }).then(function () {
                $state.go('home');
            });
        });
    };
});

app.config(function ($stateProvider) {
    $stateProvider.state('login', {
        url: '/login',
        templateUrl: 'js/login/login.html',
        controller: 'LoginCtrl'
    });
});

app.controller('LoginCtrl', function ($scope, AuthService, $state) {

    $scope.login = {};
    $scope.error = null;

    $scope.sendLogin = function (loginInfo) {

        $scope.error = null;

        AuthService.login(loginInfo).then(function (user) {
            if (user.newPass) $state.go('resetPass', { 'userId': user._id });else $state.go('home');
        })['catch'](function () {
            $scope.error = 'Invalid login credentials.';
        });
    };
});

app.config(function ($stateProvider) {

    $stateProvider.state('signup', {
        url: '/signup',
        templateUrl: 'js/signup/signup.html',
        controller: 'SignupCtrl'
    });
});

app.controller('SignupCtrl', function ($scope, AuthService, $state) {

    $scope.error = null;

    $scope.sendSignup = function (signupInfo) {
        $scope.error = null;
        AuthService.signup(signupInfo).then(function () {
            $state.go('home');
        })['catch'](function () {
            $scope.error = 'Email is taken!';
        });
    };
});

app.config(function ($stateProvider) {
    $stateProvider.state('user', {
        url: '/user/:userId',
        templateUrl: '/js/user/user.html',
        controller: function controller($scope, findUser) {
            $scope.user = findUser;
        },
        resolve: {
            findUser: function findUser($stateParams, UserFactory) {
                return UserFactory.getById($stateParams.userId).then(function (user) {
                    return user;
                });
            }
        }
    });
});

app.config(function ($stateProvider) {
    $stateProvider.state('users', {
        url: '/users',
        templateUrl: '/js/users/users.html',
        resolve: {
            users: function users(UserFactory) {
                return UserFactory.getAll();
            }
        },
        controller: function controller($scope, users, Session, $state) {
            $scope.users = users;

            //WHY NOT ON SESSION????
            // if (!Session.user || !Session.user.isAdmin){
            // 	$state.go('home');
            // }
        }
    });
});

app.factory('DweetFactory', function ($http) {
    var Dweets = function Dweets(props) {
        angular.extend(this, props);
    };

    Dweets.getAll = function () {
        return $http.get('/api/data').then(function (response) {
            return response.data;
        });
    };

    Dweets.getLatest = function () {
        return $http.get('/api/data/latest').then(function (response) {
            return response.data;
        });
    };

    Dweets.postAlert = function (alert) {
        return $http.post('/api/alerts', alert).then(function (response) {
            return response.data;
        });
    };

    return Dweets;
});

app.factory('UserFactory', function ($http) {

    var User = function User(props) {
        angular.extend(this, props);
    };

    User.getAll = function () {
        return $http.get('/api/users').then(function (response) {
            return response.data;
        });
    };

    User.getById = function (id) {
        return $http.get('/api/users/' + id).then(function (response) {
            return response.data;
        });
    };

    User.edit = function (id, props) {
        return $http.put('/api/users/' + id, props).then(function (response) {
            return response.data;
        });
    };

    User['delete'] = function (id) {
        return $http['delete']('/api/users/' + id).then(function (response) {
            return response.data;
        });
    };

    return User;
});

app.directive("editButton", function () {
    return {
        restrict: 'EA',
        templateUrl: 'js/common/directives/edit-button/edit-button.html'
    };
});

app.directive('dweetList', function () {
    return {
        restrict: 'E',
        templateUrl: '/js/common/directives/dweet/dweet-list.html'
    };
});

app.directive('navbar', function ($rootScope, AuthService, AUTH_EVENTS, $state) {

    return {
        restrict: 'E',
        scope: {},
        templateUrl: 'js/common/directives/navbar/navbar.html',
        link: function link(scope) {

            scope.items = [{ label: 'Alerts', state: 'alerts' }, { label: 'Data', state: 'data' }, { label: 'Latest', state: 'latest' }, { label: 'Users', state: 'users' }, { label: 'Documentation', state: 'docs' }];

            scope.user = null;

            scope.isLoggedIn = function () {
                return AuthService.isAuthenticated();
            };

            scope.logout = function () {
                AuthService.logout().then(function () {
                    $state.go('home');
                });
            };

            var setUser = function setUser() {
                AuthService.getLoggedInUser().then(function (user) {
                    scope.user = user;
                });
            };

            var removeUser = function removeUser() {
                scope.user = null;
            };

            setUser();

            $rootScope.$on(AUTH_EVENTS.loginSuccess, setUser);
            $rootScope.$on(AUTH_EVENTS.signupSuccess, setUser);
            $rootScope.$on(AUTH_EVENTS.logoutSuccess, removeUser);
            $rootScope.$on(AUTH_EVENTS.sessionTimeout, removeUser);
        }

    };
});

app.directive("editPassButton", function () {
    return {
        restrict: 'EA',
        templateUrl: 'js/common/directives/edit-pass-button/edit-pass-button.html'
    };
});

app.directive('userDetail', function (UserFactory, $stateParams, $state, Session) {
    return {
        restrict: 'E',
        templateUrl: '/js/common/directives/user/user-detail/user-detail.html',
        link: function link(scope) {
            scope.isDetail = true;
            scope.isAdmin = Session.user.isAdmin;
            scope.editMode = false;
            scope.editPass = false;

            //FIX THIS LINE
            if (scope.user = Session.user) scope.isOwner = true;

            scope.enableEdit = function () {
                scope.cached = angular.copy(scope.user);
                scope.editMode = true;
            };
            scope.cancelEdit = function () {
                scope.user = angular.copy(scope.cached);
                scope.editMode = false;
                scope.editPass = false;
            };
            scope.saveUser = function (user) {
                UserFactory.edit(user._id, user).then(function (updatedUser) {
                    scope.user = updatedUser;
                    scope.editMode = false;
                    scope.editPass = false;
                });
            };
            scope.deleteUser = function (user) {
                UserFactory['delete'](user).then(function () {
                    scope.editMode = false;
                    scope.editPass = false;
                    $state.go('home');
                });
            };

            scope.passwordEdit = function () {
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

app.directive('userList', function () {
    return {
        restrict: 'E',
        templateUrl: '/js/common/directives/user/user-list/user-list.html'
    };
});
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbImFwcC5qcyIsImFsZXJ0cy9hbGVydHMuanMiLCJkYXRhL2RhdGEuanMiLCJkb2NzL2RvY3MuanMiLCJmc2EvZnNhLXByZS1idWlsdC5qcyIsImhvbWUvaG9tZS5qcyIsImxhdGVzdC9sYXRlc3QuanMiLCJyZXNldFBhc3MvcmVzZXRQYXNzLmpzIiwibG9naW4vbG9naW4uanMiLCJzaWdudXAvc2lnbnVwLmpzIiwidXNlci91c2VyLmpzIiwidXNlcnMvdXNlcnMuanMiLCJjb21tb24vZmFjdG9yaWVzL2R3ZWV0LWZhY3RvcnkuanMiLCJjb21tb24vZmFjdG9yaWVzL3VzZXItZmFjdG9yeS5qcyIsImNvbW1vbi9kaXJlY3RpdmVzL2VkaXQtYnV0dG9uL2VkaXQtYnV0dG9uLmpzIiwiY29tbW9uL2RpcmVjdGl2ZXMvZHdlZXQvZHdlZXQtbGlzdC5qcyIsImNvbW1vbi9kaXJlY3RpdmVzL25hdmJhci9uYXZiYXIuanMiLCJjb21tb24vZGlyZWN0aXZlcy9lZGl0LXBhc3MtYnV0dG9uL2VkaXQtcGFzcy1idXR0b24uanMiLCJjb21tb24vZGlyZWN0aXZlcy91c2VyL3VzZXItZGV0YWlsL3VzZXItZGV0YWlsLmpzIiwiY29tbW9uL2RpcmVjdGl2ZXMvdXNlci91c2VyLWxpc3QvdXNlci1saXN0LmpzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiJBQUFBLFlBQUEsQ0FBQTtBQUNBLE1BQUEsQ0FBQSxHQUFBLEdBQUEsT0FBQSxDQUFBLE1BQUEsQ0FBQSxTQUFBLEVBQUEsQ0FBQSxXQUFBLEVBQUEsY0FBQSxFQUFBLGFBQUEsQ0FBQSxDQUFBLENBQUE7O0FBRUEsR0FBQSxDQUFBLE1BQUEsQ0FBQSxVQUFBLGtCQUFBLEVBQUEsaUJBQUEsRUFBQTs7O0FBR0Esc0JBQUEsQ0FBQSxJQUFBLENBQUEsVUFBQSxTQUFBLEVBQUEsU0FBQSxFQUFBOztBQUVBLFlBQUEsRUFBQSxHQUFBLG1CQUFBLENBQUE7QUFDQSxZQUFBLElBQUEsR0FBQSxTQUFBLENBQUEsR0FBQSxFQUFBLENBQUE7O0FBRUEsWUFBQSxFQUFBLENBQUEsSUFBQSxDQUFBLElBQUEsQ0FBQSxFQUFBO0FBQ0EsbUJBQUEsSUFBQSxDQUFBLE9BQUEsQ0FBQSxFQUFBLEVBQUEsTUFBQSxDQUFBLENBQUE7U0FDQTs7QUFFQSxlQUFBLEtBQUEsQ0FBQTtLQUNBLENBQUEsQ0FBQTs7QUFFQSxxQkFBQSxDQUFBLFNBQUEsQ0FBQSxJQUFBLENBQUEsQ0FBQTtBQUNBLHNCQUFBLENBQUEsSUFBQSxDQUFBLGlCQUFBLEVBQUEsWUFBQTtBQUNBLGNBQUEsQ0FBQSxRQUFBLENBQUEsTUFBQSxFQUFBLENBQUE7S0FDQSxDQUFBLENBQUE7O0FBRUEsc0JBQUEsQ0FBQSxTQUFBLENBQUEsR0FBQSxDQUFBLENBQUE7Q0FFQSxDQUFBLENBQUE7OztBQUdBLEdBQUEsQ0FBQSxHQUFBLENBQUEsVUFBQSxVQUFBLEVBQUEsV0FBQSxFQUFBLE1BQUEsRUFBQTs7O0FBR0EsUUFBQSw0QkFBQSxHQUFBLFNBQUEsNEJBQUEsQ0FBQSxLQUFBLEVBQUE7QUFDQSxlQUFBLEtBQUEsQ0FBQSxJQUFBLElBQUEsS0FBQSxDQUFBLElBQUEsQ0FBQSxZQUFBLENBQUE7S0FDQSxDQUFBOzs7O0FBSUEsY0FBQSxDQUFBLEdBQUEsQ0FBQSxtQkFBQSxFQUFBLFVBQUEsS0FBQSxFQUFBLE9BQUEsRUFBQSxRQUFBLEVBQUE7O0FBRUEsWUFBQSxDQUFBLDRCQUFBLENBQUEsT0FBQSxDQUFBLEVBQUE7OztBQUdBLG1CQUFBO1NBQ0E7O0FBRUEsWUFBQSxXQUFBLENBQUEsZUFBQSxFQUFBLEVBQUE7OztBQUdBLG1CQUFBO1NBQ0E7OztBQUdBLGFBQUEsQ0FBQSxjQUFBLEVBQUEsQ0FBQTs7QUFFQSxtQkFBQSxDQUFBLGVBQUEsRUFBQSxDQUFBLElBQUEsQ0FBQSxVQUFBLElBQUEsRUFBQTs7OztBQUlBLGdCQUFBLElBQUEsRUFBQTtBQUNBLHNCQUFBLENBQUEsRUFBQSxDQUFBLE9BQUEsQ0FBQSxJQUFBLEVBQUEsUUFBQSxDQUFBLENBQUE7YUFDQSxNQUFBO0FBQ0Esc0JBQUEsQ0FBQSxFQUFBLENBQUEsT0FBQSxDQUFBLENBQUE7YUFDQTtTQUNBLENBQUEsQ0FBQTtLQUVBLENBQUEsQ0FBQTtDQUVBLENBQUEsQ0FBQTs7QUNuRUEsR0FBQSxDQUFBLE1BQUEsQ0FBQSxVQUFBLGNBQUEsRUFBQTtBQUNBLGtCQUFBLENBQUEsS0FBQSxDQUFBLFFBQUEsRUFBQTtBQUNBLFdBQUEsRUFBQSxTQUFBO0FBQ0EsbUJBQUEsRUFBQSx1QkFBQTtBQUNBLGtCQUFBLEVBQUEsV0FBQTtLQUNBLENBQUEsQ0FBQTtDQUNBLENBQUEsQ0FBQTs7QUFFQSxHQUFBLENBQUEsVUFBQSxDQUFBLFdBQUEsRUFBQSxVQUFBLFlBQUEsRUFBQSxNQUFBLEVBQUEsTUFBQSxFQUFBLFVBQUEsRUFBQTs7QUFFQSxVQUFBLENBQUEsU0FBQSxHQUFBLFVBQUEsS0FBQSxFQUFBO0FBQ0EsYUFBQSxDQUFBLFVBQUEsR0FBQSxNQUFBLENBQUEsS0FBQSxDQUFBLFVBQUEsQ0FBQSxDQUFBO0FBQ0EsYUFBQSxDQUFBLFVBQUEsR0FBQSxNQUFBLENBQUEsS0FBQSxDQUFBLFVBQUEsQ0FBQSxDQUFBO0FBQ0EsYUFBQSxDQUFBLElBQUEsQ0FBQTtBQUNBLGtCQUFBLENBQUEsS0FBQSxHQUFBLEtBQUEsQ0FBQTtBQUNBLGtCQUFBLENBQUEsWUFBQSxHQUFBLElBQUEsQ0FBQTtBQUNBLGNBQUEsQ0FBQSxFQUFBLENBQUEsTUFBQSxDQUFBLENBQUE7S0FDQSxDQUFBO0NBQ0EsQ0FBQSxDQUFBOztBQ2xCQSxHQUFBLENBQUEsTUFBQSxDQUFBLFVBQUEsY0FBQSxFQUFBO0FBQ0Esa0JBQUEsQ0FDQSxLQUFBLENBQUEsTUFBQSxFQUFBO0FBQ0EsV0FBQSxFQUFBLE9BQUE7QUFDQSxtQkFBQSxFQUFBLG1CQUFBO0FBQ0Esa0JBQUEsRUFBQSxvQkFBQSxNQUFBLEVBQUEsU0FBQSxFQUFBO0FBQ0Esa0JBQUEsQ0FBQSxNQUFBLEdBQUEsU0FBQSxDQUFBO1NBQ0E7QUFDQSxlQUFBLEVBQUE7Ozs7QUFJQSxxQkFBQSxFQUFBLG1CQUFBLFlBQUEsRUFBQTtBQUNBLHVCQUFBLFlBQUEsQ0FBQSxNQUFBLEVBQUEsQ0FBQTthQUNBO1NBQ0E7S0FDQSxDQUFBLENBQUE7Q0FDQSxDQUFBLENBQUE7O0FDakJBLEdBQUEsQ0FBQSxNQUFBLENBQUEsVUFBQSxjQUFBLEVBQUE7QUFDQSxrQkFBQSxDQUFBLEtBQUEsQ0FBQSxNQUFBLEVBQUE7QUFDQSxXQUFBLEVBQUEsT0FBQTtBQUNBLG1CQUFBLEVBQUEsbUJBQUE7S0FDQSxDQUFBLENBQUE7Q0FDQSxDQUFBLENBQUE7O0FDTEEsQ0FBQSxZQUFBOztBQUVBLGdCQUFBLENBQUE7OztBQUdBLFFBQUEsQ0FBQSxNQUFBLENBQUEsT0FBQSxFQUFBLE1BQUEsSUFBQSxLQUFBLENBQUEsd0JBQUEsQ0FBQSxDQUFBOztBQUVBLFFBQUEsR0FBQSxHQUFBLE9BQUEsQ0FBQSxNQUFBLENBQUEsYUFBQSxFQUFBLEVBQUEsQ0FBQSxDQUFBOztBQUVBLE9BQUEsQ0FBQSxPQUFBLENBQUEsUUFBQSxFQUFBLFlBQUE7QUFDQSxZQUFBLENBQUEsTUFBQSxDQUFBLEVBQUEsRUFBQSxNQUFBLElBQUEsS0FBQSxDQUFBLHNCQUFBLENBQUEsQ0FBQTtBQUNBLGVBQUEsTUFBQSxDQUFBLEVBQUEsQ0FBQSxNQUFBLENBQUEsUUFBQSxDQUFBLE1BQUEsQ0FBQSxDQUFBO0tBQ0EsQ0FBQSxDQUFBOzs7OztBQUtBLE9BQUEsQ0FBQSxRQUFBLENBQUEsYUFBQSxFQUFBO0FBQ0Esb0JBQUEsRUFBQSxvQkFBQTtBQUNBLG1CQUFBLEVBQUEsbUJBQUE7QUFDQSxxQkFBQSxFQUFBLHFCQUFBO0FBQ0Esb0JBQUEsRUFBQSxvQkFBQTtBQUNBLHFCQUFBLEVBQUEscUJBQUE7QUFDQSxzQkFBQSxFQUFBLHNCQUFBO0FBQ0Esd0JBQUEsRUFBQSx3QkFBQTtBQUNBLHFCQUFBLEVBQUEscUJBQUE7S0FDQSxDQUFBLENBQUE7O0FBRUEsT0FBQSxDQUFBLE9BQUEsQ0FBQSxpQkFBQSxFQUFBLFVBQUEsVUFBQSxFQUFBLEVBQUEsRUFBQSxXQUFBLEVBQUE7QUFDQSxZQUFBLFVBQUEsR0FBQTtBQUNBLGVBQUEsRUFBQSxXQUFBLENBQUEsZ0JBQUE7QUFDQSxlQUFBLEVBQUEsV0FBQSxDQUFBLGFBQUE7QUFDQSxlQUFBLEVBQUEsV0FBQSxDQUFBLGNBQUE7QUFDQSxlQUFBLEVBQUEsV0FBQSxDQUFBLGNBQUE7U0FDQSxDQUFBO0FBQ0EsZUFBQTtBQUNBLHlCQUFBLEVBQUEsdUJBQUEsUUFBQSxFQUFBO0FBQ0EsMEJBQUEsQ0FBQSxVQUFBLENBQUEsVUFBQSxDQUFBLFFBQUEsQ0FBQSxNQUFBLENBQUEsRUFBQSxRQUFBLENBQUEsQ0FBQTtBQUNBLHVCQUFBLEVBQUEsQ0FBQSxNQUFBLENBQUEsUUFBQSxDQUFBLENBQUE7YUFDQTtTQUNBLENBQUE7S0FDQSxDQUFBLENBQUE7O0FBRUEsT0FBQSxDQUFBLE1BQUEsQ0FBQSxVQUFBLGFBQUEsRUFBQTtBQUNBLHFCQUFBLENBQUEsWUFBQSxDQUFBLElBQUEsQ0FBQSxDQUNBLFdBQUEsRUFDQSxVQUFBLFNBQUEsRUFBQTtBQUNBLG1CQUFBLFNBQUEsQ0FBQSxHQUFBLENBQUEsaUJBQUEsQ0FBQSxDQUFBO1NBQ0EsQ0FDQSxDQUFBLENBQUE7S0FDQSxDQUFBLENBQUE7O0FBRUEsT0FBQSxDQUFBLE9BQUEsQ0FBQSxhQUFBLEVBQUEsVUFBQSxLQUFBLEVBQUEsT0FBQSxFQUFBLFVBQUEsRUFBQSxXQUFBLEVBQUEsRUFBQSxFQUFBOztBQUVBLGlCQUFBLGlCQUFBLENBQUEsUUFBQSxFQUFBO0FBQ0EsZ0JBQUEsSUFBQSxHQUFBLFFBQUEsQ0FBQSxJQUFBLENBQUE7QUFDQSxtQkFBQSxDQUFBLE1BQUEsQ0FBQSxJQUFBLENBQUEsRUFBQSxFQUFBLElBQUEsQ0FBQSxJQUFBLENBQUEsQ0FBQTtBQUNBLHNCQUFBLENBQUEsVUFBQSxDQUFBLFdBQUEsQ0FBQSxZQUFBLENBQUEsQ0FBQTtBQUNBLG1CQUFBLElBQUEsQ0FBQSxJQUFBLENBQUE7U0FDQTs7O0FBR0EsaUJBQUEsa0JBQUEsQ0FBQSxRQUFBLEVBQUE7QUFDQSxnQkFBQSxJQUFBLEdBQUEsUUFBQSxDQUFBLElBQUEsQ0FBQTtBQUNBLG1CQUFBLENBQUEsTUFBQSxDQUFBLElBQUEsQ0FBQSxFQUFBLEVBQUEsSUFBQSxDQUFBLElBQUEsQ0FBQSxDQUFBO0FBQ0Esc0JBQUEsQ0FBQSxVQUFBLENBQUEsV0FBQSxDQUFBLGFBQUEsQ0FBQSxDQUFBO0FBQ0EsbUJBQUEsSUFBQSxDQUFBLElBQUEsQ0FBQTtTQUNBOzs7O0FBSUEsWUFBQSxDQUFBLGVBQUEsR0FBQSxZQUFBO0FBQ0EsbUJBQUEsQ0FBQSxDQUFBLE9BQUEsQ0FBQSxJQUFBLENBQUE7U0FDQSxDQUFBOztBQUVBLFlBQUEsQ0FBQSxlQUFBLEdBQUEsVUFBQSxVQUFBLEVBQUE7Ozs7Ozs7Ozs7QUFVQSxnQkFBQSxJQUFBLENBQUEsZUFBQSxFQUFBLElBQUEsVUFBQSxLQUFBLElBQUEsRUFBQTtBQUNBLHVCQUFBLEVBQUEsQ0FBQSxJQUFBLENBQUEsT0FBQSxDQUFBLElBQUEsQ0FBQSxDQUFBO2FBQ0E7Ozs7O0FBS0EsbUJBQUEsS0FBQSxDQUFBLEdBQUEsQ0FBQSxVQUFBLENBQUEsQ0FBQSxJQUFBLENBQUEsaUJBQUEsQ0FBQSxTQUFBLENBQUEsWUFBQTtBQUNBLHVCQUFBLElBQUEsQ0FBQTthQUNBLENBQUEsQ0FBQTtTQUVBLENBQUE7O0FBRUEsWUFBQSxDQUFBLEtBQUEsR0FBQSxVQUFBLFdBQUEsRUFBQTtBQUNBLG1CQUFBLEtBQUEsQ0FBQSxJQUFBLENBQUEsUUFBQSxFQUFBLFdBQUEsQ0FBQSxDQUNBLElBQUEsQ0FBQSxpQkFBQSxDQUFBLFNBQ0EsQ0FBQSxZQUFBO0FBQ0EsdUJBQUEsRUFBQSxDQUFBLE1BQUEsQ0FBQSxFQUFBLE9BQUEsRUFBQSw0QkFBQSxFQUFBLENBQUEsQ0FBQTthQUNBLENBQUEsQ0FBQTtTQUNBLENBQUE7O0FBRUEsWUFBQSxDQUFBLE1BQUEsR0FBQSxZQUFBO0FBQ0EsbUJBQUEsS0FBQSxDQUFBLEdBQUEsQ0FBQSxTQUFBLENBQUEsQ0FBQSxJQUFBLENBQUEsWUFBQTtBQUNBLHVCQUFBLENBQUEsT0FBQSxFQUFBLENBQUE7QUFDQSwwQkFBQSxDQUFBLFVBQUEsQ0FBQSxXQUFBLENBQUEsYUFBQSxDQUFBLENBQUE7YUFDQSxDQUFBLENBQUE7U0FDQSxDQUFBOztBQUVBLFlBQUEsQ0FBQSxNQUFBLEdBQUEsVUFBQSxXQUFBLEVBQUE7QUFDQSxtQkFBQSxLQUFBLENBQUEsSUFBQSxDQUFBLFNBQUEsRUFBQSxXQUFBLENBQUEsQ0FDQSxJQUFBLENBQUEsa0JBQUEsQ0FBQSxDQUFBO1NBQ0EsQ0FBQTtLQUdBLENBQUEsQ0FBQTs7QUFFQSxPQUFBLENBQUEsT0FBQSxDQUFBLFNBQUEsRUFBQSxVQUFBLFVBQUEsRUFBQSxXQUFBLEVBQUE7O0FBRUEsWUFBQSxJQUFBLEdBQUEsSUFBQSxDQUFBOztBQUVBLGtCQUFBLENBQUEsR0FBQSxDQUFBLFdBQUEsQ0FBQSxnQkFBQSxFQUFBLFlBQUE7QUFDQSxnQkFBQSxDQUFBLE9BQUEsRUFBQSxDQUFBO1NBQ0EsQ0FBQSxDQUFBOztBQUVBLGtCQUFBLENBQUEsR0FBQSxDQUFBLFdBQUEsQ0FBQSxjQUFBLEVBQUEsWUFBQTtBQUNBLGdCQUFBLENBQUEsT0FBQSxFQUFBLENBQUE7U0FDQSxDQUFBLENBQUE7O0FBRUEsWUFBQSxDQUFBLEVBQUEsR0FBQSxJQUFBLENBQUE7QUFDQSxZQUFBLENBQUEsSUFBQSxHQUFBLElBQUEsQ0FBQTs7QUFFQSxZQUFBLENBQUEsTUFBQSxHQUFBLFVBQUEsU0FBQSxFQUFBLElBQUEsRUFBQTtBQUNBLGdCQUFBLENBQUEsRUFBQSxHQUFBLFNBQUEsQ0FBQTtBQUNBLGdCQUFBLENBQUEsSUFBQSxHQUFBLElBQUEsQ0FBQTtTQUNBLENBQUE7O0FBRUEsWUFBQSxDQUFBLE9BQUEsR0FBQSxZQUFBO0FBQ0EsZ0JBQUEsQ0FBQSxFQUFBLEdBQUEsSUFBQSxDQUFBO0FBQ0EsZ0JBQUEsQ0FBQSxJQUFBLEdBQUEsSUFBQSxDQUFBO1NBQ0EsQ0FBQTtLQUVBLENBQUEsQ0FBQTtDQUVBLENBQUEsRUFBQSxDQUFBOztBQ3BKQSxHQUFBLENBQUEsTUFBQSxDQUFBLFVBQUEsY0FBQSxFQUFBO0FBQ0Esa0JBQUEsQ0FBQSxLQUFBLENBQUEsTUFBQSxFQUFBO0FBQ0EsV0FBQSxFQUFBLEdBQUE7QUFDQSxtQkFBQSxFQUFBLG1CQUFBO0FBQ0Esa0JBQUEsRUFBQSxvQkFBQSxNQUFBLEVBQUEsWUFBQSxFQUFBLFVBQUEsRUFBQSxVQUFBLEVBQUE7O0FBRUEsa0JBQUEsQ0FBQSxVQUFBLEdBQUEsRUFBQSxDQUFBO0FBQ0Esc0JBQUEsQ0FBQSxVQUFBLEdBQUEsRUFBQSxDQUFBOztBQUVBLGtCQUFBLENBQUEsS0FBQSxHQUFBLElBQUEsQ0FBQTs7O0FBR0Esd0JBQUEsQ0FBQSxTQUFBLEVBQUEsQ0FDQSxJQUFBLENBQUEsVUFBQSxLQUFBLEVBQUE7QUFDQSxzQkFBQSxDQUFBLFNBQUEsR0FBQSxLQUFBLENBQUE7YUFDQSxDQUFBLENBQUE7Ozs7QUFJQSxnQkFBQSxLQUFBLEdBQUEsSUFBQSxVQUFBLEVBQUEsQ0FBQTtBQUNBLGdCQUFBLEtBQUEsR0FBQSxJQUFBLFVBQUEsRUFBQSxDQUFBOzs7QUFHQSxnQkFBQSxVQUFBLENBQUEsS0FBQSxFQUFBO0FBQ0EsMkJBQUEsQ0FBQSxZQUFBO0FBQ0EsZ0NBQUEsQ0FBQSxTQUFBLEVBQUEsQ0FDQSxJQUFBLENBQUEsVUFBQSxLQUFBLEVBQUE7QUFDQSw4QkFBQSxDQUFBLFNBQUEsR0FBQSxLQUFBLENBQUE7cUJBQ0EsQ0FBQSxDQUNBLElBQUEsQ0FBQSxZQUFBO0FBQ0EsNEJBQUEsVUFBQSxHQUFBLElBQUEsQ0FBQSxNQUFBLEVBQUEsR0FBQSxDQUFBLEdBQUEsRUFBQSxDQUFBO0FBQ0EsNEJBQUEsTUFBQSxDQUFBLFNBQUEsQ0FBQSxPQUFBLElBQUEsTUFBQSxDQUFBLFNBQUEsQ0FBQSxPQUFBLEVBQUE7QUFDQSxrQ0FBQSxDQUFBLFVBQUEsQ0FBQSxJQUFBLENBQUEsTUFBQSxDQUFBLFNBQUEsQ0FBQSxDQUFBO0FBQ0Esa0NBQUEsQ0FBQSxTQUFBLEdBQUEsTUFBQSxDQUFBLFNBQUEsQ0FBQTtBQUNBLGlDQUFBLENBQUEsTUFBQSxDQUFBLElBQUEsSUFBQSxFQUFBLENBQUEsT0FBQSxFQUFBLEVBQUEsTUFBQSxDQUFBLFNBQUEsQ0FBQSxPQUFBLENBQUEsYUFBQSxDQUFBLENBQUEsQ0FBQTs7QUFFQSxpQ0FBQSxDQUFBLE1BQUEsQ0FBQSxJQUFBLElBQUEsRUFBQSxDQUFBLE9BQUEsRUFBQSxFQUFBLFVBQUEsQ0FBQSxDQUFBO3lCQUNBOztBQUVBLDRCQUFBLE1BQUEsQ0FBQSxTQUFBLENBQUEsT0FBQSxDQUFBLGFBQUEsQ0FBQSxHQUFBLFVBQUEsQ0FBQSxLQUFBLENBQUEsVUFBQSxJQUFBLE1BQUEsQ0FBQSxTQUFBLENBQUEsT0FBQSxDQUFBLGFBQUEsQ0FBQSxHQUFBLFVBQUEsQ0FBQSxLQUFBLENBQUEsVUFBQSxFQUFBO0FBQ0EsbUNBQUEsQ0FBQSxHQUFBLENBQUEscUJBQUEsQ0FBQSxDQUFBO0FBQ0EsZ0NBQUEsUUFBQSxHQUFBLElBQUEsSUFBQSxFQUFBLENBQUE7QUFDQSxnQ0FBQSxRQUFBLEdBQUEsUUFBQSxDQUFBLFFBQUEsRUFBQSxDQUFBLEtBQUEsQ0FBQSxFQUFBLENBQUEsQ0FBQTtBQUNBLHNDQUFBLENBQUEsS0FBQSxDQUFBLElBQUEsR0FBQSxRQUFBLENBQUE7QUFDQSxzQ0FBQSxDQUFBLEtBQUEsQ0FBQSxJQUFBLEdBQUEsTUFBQSxDQUFBLFNBQUEsQ0FBQSxPQUFBLENBQUEsYUFBQSxDQUFBLENBQUE7QUFDQSx3Q0FBQSxDQUFBLFNBQUEsQ0FBQSxVQUFBLENBQUEsS0FBQSxDQUFBLENBQ0EsSUFBQSxDQUFBLFVBQUEsV0FBQSxFQUFBO0FBQ0EsMENBQUEsQ0FBQSxVQUFBLENBQUEsSUFBQSxDQUFBLFdBQUEsQ0FBQSxDQUFBO0FBQ0Esc0NBQUEsQ0FBQSxLQUFBLEdBQUEsZ0NBQUEsQ0FBQTs2QkFDQSxDQUFBLENBQUE7eUJBQ0E7OztBQUdBLDRCQUFBLFVBQUEsR0FBQSxVQUFBLENBQUEsS0FBQSxDQUFBLFVBQUEsSUFBQSxVQUFBLEdBQUEsVUFBQSxDQUFBLEtBQUEsQ0FBQSxVQUFBLEVBQUE7QUFDQSxtQ0FBQSxDQUFBLEdBQUEsQ0FBQSx1QkFBQSxDQUFBLENBQUE7QUFDQSxnQ0FBQSxRQUFBLEdBQUEsSUFBQSxJQUFBLEVBQUEsQ0FBQTtBQUNBLGdDQUFBLFFBQUEsR0FBQSxRQUFBLENBQUEsUUFBQSxFQUFBLENBQUEsS0FBQSxDQUFBLEVBQUEsQ0FBQSxDQUFBO0FBQ0Esc0NBQUEsQ0FBQSxLQUFBLENBQUEsSUFBQSxHQUFBLFFBQUEsQ0FBQTtBQUNBLHNDQUFBLENBQUEsS0FBQSxDQUFBLElBQUEsR0FBQSxVQUFBLENBQUE7QUFDQSx3Q0FBQSxDQUFBLFNBQUEsQ0FBQSxVQUFBLENBQUEsS0FBQSxDQUFBLENBQ0EsSUFBQSxDQUFBLFVBQUEsV0FBQSxFQUFBO0FBQ0EsMENBQUEsQ0FBQSxVQUFBLENBQUEsSUFBQSxDQUFBLFdBQUEsQ0FBQSxDQUFBO0FBQ0Esc0NBQUEsQ0FBQSxLQUFBLEdBQUEsZ0NBQUEsQ0FBQTs2QkFDQSxDQUFBLENBQUE7eUJBQ0E7O0FBRUEsK0JBQUEsTUFBQSxDQUFBLFVBQUEsQ0FBQSxNQUFBLEdBQUEsR0FBQSxFQUFBO0FBQ0Esa0NBQUEsQ0FBQSxVQUFBLENBQUEsS0FBQSxFQUFBLENBQUE7eUJBQ0E7QUFDQSwrQkFBQSxNQUFBLENBQUEsVUFBQSxDQUFBLE1BQUEsR0FBQSxHQUFBLEVBQUE7QUFDQSxrQ0FBQSxDQUFBLFVBQUEsQ0FBQSxLQUFBLEVBQUEsQ0FBQTt5QkFDQTtxQkFDQSxDQUFBLENBQUE7aUJBQ0EsRUFBQSxHQUFBLENBQUEsQ0FBQTthQUNBOzs7QUFHQSxnQkFBQSxRQUFBLEdBQUEsSUFBQSxhQUFBLENBQUE7QUFDQSxvQkFBQSxFQUFBO0FBQ0EsK0JBQUEsRUFBQSxtQkFBQTtBQUNBLDZCQUFBLEVBQUEsZUFBQTtBQUNBLDZCQUFBLEVBQUEsQ0FBQTtBQUNBLGlDQUFBLEVBQUEsR0FBQTtBQUNBLG9DQUFBLEVBQUEsQ0FBQTtpQkFDQTtBQUNBLHdCQUFBLEVBQUEsVUFBQSxDQUFBLEtBQUEsQ0FBQSxVQUFBLEdBQUEsS0FBQTtBQUNBLHdCQUFBLEVBQUEsVUFBQSxDQUFBLEtBQUEsQ0FBQSxVQUFBLEdBQUEsS0FBQTs7O0FBR0Esa0NBQUEsRUFBQSxhQUFBLENBQUEsYUFBQTs7O0FBR0EsK0JBQUEsRUFBQSxDQUFBO0FBQ0EseUJBQUEsRUFBQSxTQUFBO0FBQ0EsNkJBQUEsRUFBQSxDQUFBO0FBQ0EseUJBQUEsRUFBQSxVQUFBLENBQUEsS0FBQSxDQUFBLFVBQUEsSUFBQSxFQUFBO2lCQUNBLEVBQUE7QUFDQSx5QkFBQSxFQUFBLFNBQUE7QUFDQSw2QkFBQSxFQUFBLENBQUE7QUFDQSx5QkFBQSxFQUFBLFVBQUEsQ0FBQSxLQUFBLENBQUEsVUFBQSxJQUFBLEVBQUE7aUJBQ0EsQ0FBQTthQUNBLENBQUEsQ0FBQTs7QUFFQSxvQkFBQSxDQUFBLGFBQUEsQ0FBQSxLQUFBLEVBQUE7QUFDQSwyQkFBQSxFQUFBLGdCQUFBO0FBQ0EseUJBQUEsRUFBQSxzQkFBQTtBQUNBLHlCQUFBLEVBQUEsQ0FBQTthQUNBLENBQUEsQ0FBQTtBQUNBLG9CQUFBLENBQUEsYUFBQSxDQUFBLEtBQUEsRUFBQTtBQUNBLDJCQUFBLEVBQUEsa0JBQUE7QUFDQSx5QkFBQSxFQUFBLHdCQUFBO0FBQ0EseUJBQUEsRUFBQSxDQUFBO2FBQ0EsQ0FBQSxDQUFBOztBQUVBLG9CQUFBLENBQUEsUUFBQSxDQUFBLFFBQUEsQ0FBQSxjQUFBLENBQUEsT0FBQSxDQUFBLEVBQUEsR0FBQSxDQUFBLENBQUE7U0FDQTtBQUNBLGVBQUEsRUFBQTtBQUNBLHNCQUFBLEVBQUEsb0JBQUEsWUFBQSxFQUFBO0FBQ0EsdUJBQUEsWUFBQSxDQUFBLFNBQUEsRUFBQSxDQUNBLElBQUEsQ0FBQSxVQUFBLEtBQUEsRUFBQTtBQUNBLDJCQUFBLEtBQUEsQ0FBQSxPQUFBLENBQUEsYUFBQSxDQUFBLENBQUE7aUJBQ0EsQ0FBQSxDQUFBO2FBQ0E7U0FDQTtLQUNBLENBQUEsQ0FBQTtDQUNBLENBQUEsQ0FBQTs7QUM3SEEsR0FBQSxDQUFBLE1BQUEsQ0FBQSxVQUFBLGNBQUEsRUFBQTtBQUNBLGtCQUFBLENBQUEsS0FBQSxDQUFBLFFBQUEsRUFBQTtBQUNBLFdBQUEsRUFBQSxjQUFBO0FBQ0EsbUJBQUEsRUFBQSx1QkFBQTtBQUNBLGtCQUFBLEVBQUEsb0JBQUEsTUFBQSxFQUFBLFdBQUEsRUFBQTtBQUNBLGtCQUFBLENBQUEsV0FBQSxHQUFBLFdBQUEsQ0FBQTtTQUNBO0FBQ0EsZUFBQSxFQUFBO0FBQ0EsdUJBQUEsRUFBQSxxQkFBQSxZQUFBLEVBQUE7QUFDQSx1QkFBQSxZQUFBLENBQUEsU0FBQSxFQUFBLENBQUE7YUFDQTtTQUNBO0tBQ0EsQ0FBQSxDQUFBO0NBQ0EsQ0FBQSxDQUFBOztBQ2JBLEdBQUEsQ0FBQSxNQUFBLENBQUEsVUFBQSxjQUFBLEVBQUE7QUFDQSxrQkFBQSxDQUNBLEtBQUEsQ0FBQSxXQUFBLEVBQUE7QUFDQSxXQUFBLEVBQUEsZ0JBQUE7QUFDQSxtQkFBQSxFQUFBLDZCQUFBO0FBQ0Esa0JBQUEsRUFBQSxXQUFBO0tBQ0EsQ0FBQSxDQUFBO0NBQ0EsQ0FBQSxDQUFBOztBQUVBLEdBQUEsQ0FBQSxVQUFBLENBQUEsV0FBQSxFQUFBLFVBQUEsTUFBQSxFQUFBLFdBQUEsRUFBQSxZQUFBLEVBQUEsV0FBQSxFQUFBLE1BQUEsRUFBQTs7QUFFQSxVQUFBLENBQUEsU0FBQSxHQUFBLFVBQUEsT0FBQSxFQUFBO0FBQ0EsbUJBQUEsQ0FBQSxJQUFBLENBQUEsWUFBQSxDQUFBLE1BQUEsRUFBQSxFQUFBLFNBQUEsRUFBQSxLQUFBLEVBQUEsVUFBQSxFQUFBLE9BQUEsRUFBQSxDQUFBLENBQ0EsSUFBQSxDQUFBLFVBQUEsSUFBQSxFQUFBO0FBQ0EsdUJBQUEsQ0FBQSxLQUFBLENBQUEsRUFBQSxLQUFBLEVBQUEsSUFBQSxDQUFBLEtBQUEsRUFBQSxRQUFBLEVBQUEsT0FBQSxFQUFBLENBQUEsQ0FDQSxJQUFBLENBQUEsWUFBQTtBQUNBLHNCQUFBLENBQUEsRUFBQSxDQUFBLE1BQUEsQ0FBQSxDQUFBO2FBQ0EsQ0FBQSxDQUFBO1NBQ0EsQ0FBQSxDQUFBO0tBQ0EsQ0FBQTtDQUNBLENBQUEsQ0FBQTs7QUNwQkEsR0FBQSxDQUFBLE1BQUEsQ0FBQSxVQUFBLGNBQUEsRUFBQTtBQUNBLGtCQUFBLENBQUEsS0FBQSxDQUFBLE9BQUEsRUFBQTtBQUNBLFdBQUEsRUFBQSxRQUFBO0FBQ0EsbUJBQUEsRUFBQSxxQkFBQTtBQUNBLGtCQUFBLEVBQUEsV0FBQTtLQUNBLENBQUEsQ0FBQTtDQUNBLENBQUEsQ0FBQTs7QUFFQSxHQUFBLENBQUEsVUFBQSxDQUFBLFdBQUEsRUFBQSxVQUFBLE1BQUEsRUFBQSxXQUFBLEVBQUEsTUFBQSxFQUFBOztBQUVBLFVBQUEsQ0FBQSxLQUFBLEdBQUEsRUFBQSxDQUFBO0FBQ0EsVUFBQSxDQUFBLEtBQUEsR0FBQSxJQUFBLENBQUE7O0FBRUEsVUFBQSxDQUFBLFNBQUEsR0FBQSxVQUFBLFNBQUEsRUFBQTs7QUFFQSxjQUFBLENBQUEsS0FBQSxHQUFBLElBQUEsQ0FBQTs7QUFFQSxtQkFBQSxDQUFBLEtBQUEsQ0FBQSxTQUFBLENBQUEsQ0FBQSxJQUFBLENBQUEsVUFBQSxJQUFBLEVBQUE7QUFDQSxnQkFBQSxJQUFBLENBQUEsT0FBQSxFQUFBLE1BQUEsQ0FBQSxFQUFBLENBQUEsV0FBQSxFQUFBLEVBQUEsUUFBQSxFQUFBLElBQUEsQ0FBQSxHQUFBLEVBQUEsQ0FBQSxDQUFBLEtBQ0EsTUFBQSxDQUFBLEVBQUEsQ0FBQSxNQUFBLENBQUEsQ0FBQTtTQUNBLENBQUEsU0FBQSxDQUFBLFlBQUE7QUFDQSxrQkFBQSxDQUFBLEtBQUEsR0FBQSw0QkFBQSxDQUFBO1NBQ0EsQ0FBQSxDQUFBO0tBQ0EsQ0FBQTtDQUNBLENBQUEsQ0FBQTs7QUN4QkEsR0FBQSxDQUFBLE1BQUEsQ0FBQSxVQUFBLGNBQUEsRUFBQTs7QUFFQSxrQkFBQSxDQUFBLEtBQUEsQ0FBQSxRQUFBLEVBQUE7QUFDQSxXQUFBLEVBQUEsU0FBQTtBQUNBLG1CQUFBLEVBQUEsdUJBQUE7QUFDQSxrQkFBQSxFQUFBLFlBQUE7S0FDQSxDQUFBLENBQUE7Q0FFQSxDQUFBLENBQUE7O0FBRUEsR0FBQSxDQUFBLFVBQUEsQ0FBQSxZQUFBLEVBQUEsVUFBQSxNQUFBLEVBQUEsV0FBQSxFQUFBLE1BQUEsRUFBQTs7QUFFQSxVQUFBLENBQUEsS0FBQSxHQUFBLElBQUEsQ0FBQTs7QUFFQSxVQUFBLENBQUEsVUFBQSxHQUFBLFVBQUEsVUFBQSxFQUFBO0FBQ0EsY0FBQSxDQUFBLEtBQUEsR0FBQSxJQUFBLENBQUE7QUFDQSxtQkFBQSxDQUFBLE1BQUEsQ0FBQSxVQUFBLENBQUEsQ0FDQSxJQUFBLENBQUEsWUFBQTtBQUNBLGtCQUFBLENBQUEsRUFBQSxDQUFBLE1BQUEsQ0FBQSxDQUFBO1NBQ0EsQ0FBQSxTQUNBLENBQUEsWUFBQTtBQUNBLGtCQUFBLENBQUEsS0FBQSxHQUFBLGlCQUFBLENBQUE7U0FDQSxDQUFBLENBQUE7S0FFQSxDQUFBO0NBRUEsQ0FBQSxDQUFBOztBQzFCQSxHQUFBLENBQUEsTUFBQSxDQUFBLFVBQUEsY0FBQSxFQUFBO0FBQ0Esa0JBQUEsQ0FDQSxLQUFBLENBQUEsTUFBQSxFQUFBO0FBQ0EsV0FBQSxFQUFBLGVBQUE7QUFDQSxtQkFBQSxFQUFBLG9CQUFBO0FBQ0Esa0JBQUEsRUFBQSxvQkFBQSxNQUFBLEVBQUEsUUFBQSxFQUFBO0FBQ0Esa0JBQUEsQ0FBQSxJQUFBLEdBQUEsUUFBQSxDQUFBO1NBQ0E7QUFDQSxlQUFBLEVBQUE7QUFDQSxvQkFBQSxFQUFBLGtCQUFBLFlBQUEsRUFBQSxXQUFBLEVBQUE7QUFDQSx1QkFBQSxXQUFBLENBQUEsT0FBQSxDQUFBLFlBQUEsQ0FBQSxNQUFBLENBQUEsQ0FDQSxJQUFBLENBQUEsVUFBQSxJQUFBLEVBQUE7QUFDQSwyQkFBQSxJQUFBLENBQUE7aUJBQ0EsQ0FBQSxDQUFBO2FBQ0E7U0FDQTtLQUNBLENBQUEsQ0FBQTtDQUNBLENBQUEsQ0FBQTs7QUNqQkEsR0FBQSxDQUFBLE1BQUEsQ0FBQSxVQUFBLGNBQUEsRUFBQTtBQUNBLGtCQUFBLENBQUEsS0FBQSxDQUFBLE9BQUEsRUFBQTtBQUNBLFdBQUEsRUFBQSxRQUFBO0FBQ0EsbUJBQUEsRUFBQSxzQkFBQTtBQUNBLGVBQUEsRUFBQTtBQUNBLGlCQUFBLEVBQUEsZUFBQSxXQUFBLEVBQUE7QUFDQSx1QkFBQSxXQUFBLENBQUEsTUFBQSxFQUFBLENBQUE7YUFDQTtTQUNBO0FBQ0Esa0JBQUEsRUFBQSxvQkFBQSxNQUFBLEVBQUEsS0FBQSxFQUFBLE9BQUEsRUFBQSxNQUFBLEVBQUE7QUFDQSxrQkFBQSxDQUFBLEtBQUEsR0FBQSxLQUFBLENBQUE7Ozs7OztTQU1BO0tBQ0EsQ0FBQSxDQUFBO0NBQ0EsQ0FBQSxDQUFBOztBQ2xCQSxHQUFBLENBQUEsT0FBQSxDQUFBLGNBQUEsRUFBQSxVQUFBLEtBQUEsRUFBQTtBQUNBLFFBQUEsTUFBQSxHQUFBLFNBQUEsTUFBQSxDQUFBLEtBQUEsRUFBQTtBQUNBLGVBQUEsQ0FBQSxNQUFBLENBQUEsSUFBQSxFQUFBLEtBQUEsQ0FBQSxDQUFBO0tBQ0EsQ0FBQTs7QUFFQSxVQUFBLENBQUEsTUFBQSxHQUFBLFlBQUE7QUFDQSxlQUFBLEtBQUEsQ0FBQSxHQUFBLENBQUEsV0FBQSxDQUFBLENBQ0EsSUFBQSxDQUFBLFVBQUEsUUFBQSxFQUFBO0FBQ0EsbUJBQUEsUUFBQSxDQUFBLElBQUEsQ0FBQTtTQUNBLENBQUEsQ0FBQTtLQUNBLENBQUE7O0FBRUEsVUFBQSxDQUFBLFNBQUEsR0FBQSxZQUFBO0FBQ0EsZUFBQSxLQUFBLENBQUEsR0FBQSxDQUFBLGtCQUFBLENBQUEsQ0FDQSxJQUFBLENBQUEsVUFBQSxRQUFBLEVBQUE7QUFDQSxtQkFBQSxRQUFBLENBQUEsSUFBQSxDQUFBO1NBQ0EsQ0FBQSxDQUFBO0tBQ0EsQ0FBQTs7QUFFQSxVQUFBLENBQUEsU0FBQSxHQUFBLFVBQUEsS0FBQSxFQUFBO0FBQ0EsZUFBQSxLQUFBLENBQUEsSUFBQSxDQUFBLGFBQUEsRUFBQSxLQUFBLENBQUEsQ0FDQSxJQUFBLENBQUEsVUFBQSxRQUFBLEVBQUE7QUFDQSxtQkFBQSxRQUFBLENBQUEsSUFBQSxDQUFBO1NBQ0EsQ0FBQSxDQUFBO0tBQ0EsQ0FBQTs7QUFFQSxXQUFBLE1BQUEsQ0FBQTtDQUNBLENBQUEsQ0FBQTs7QUMzQkEsR0FBQSxDQUFBLE9BQUEsQ0FBQSxhQUFBLEVBQUEsVUFBQSxLQUFBLEVBQUE7O0FBRUEsUUFBQSxJQUFBLEdBQUEsU0FBQSxJQUFBLENBQUEsS0FBQSxFQUFBO0FBQ0EsZUFBQSxDQUFBLE1BQUEsQ0FBQSxJQUFBLEVBQUEsS0FBQSxDQUFBLENBQUE7S0FDQSxDQUFBOztBQUVBLFFBQUEsQ0FBQSxNQUFBLEdBQUEsWUFBQTtBQUNBLGVBQUEsS0FBQSxDQUFBLEdBQUEsQ0FBQSxZQUFBLENBQUEsQ0FDQSxJQUFBLENBQUEsVUFBQSxRQUFBLEVBQUE7QUFDQSxtQkFBQSxRQUFBLENBQUEsSUFBQSxDQUFBO1NBQ0EsQ0FBQSxDQUFBO0tBQ0EsQ0FBQTs7QUFFQSxRQUFBLENBQUEsT0FBQSxHQUFBLFVBQUEsRUFBQSxFQUFBO0FBQ0EsZUFBQSxLQUFBLENBQUEsR0FBQSxDQUFBLGFBQUEsR0FBQSxFQUFBLENBQUEsQ0FDQSxJQUFBLENBQUEsVUFBQSxRQUFBLEVBQUE7QUFDQSxtQkFBQSxRQUFBLENBQUEsSUFBQSxDQUFBO1NBQ0EsQ0FBQSxDQUFBO0tBQ0EsQ0FBQTs7QUFFQSxRQUFBLENBQUEsSUFBQSxHQUFBLFVBQUEsRUFBQSxFQUFBLEtBQUEsRUFBQTtBQUNBLGVBQUEsS0FBQSxDQUFBLEdBQUEsQ0FBQSxhQUFBLEdBQUEsRUFBQSxFQUFBLEtBQUEsQ0FBQSxDQUNBLElBQUEsQ0FBQSxVQUFBLFFBQUEsRUFBQTtBQUNBLG1CQUFBLFFBQUEsQ0FBQSxJQUFBLENBQUE7U0FDQSxDQUFBLENBQUE7S0FDQSxDQUFBOztBQUVBLFFBQUEsVUFBQSxHQUFBLFVBQUEsRUFBQSxFQUFBO0FBQ0EsZUFBQSxLQUFBLFVBQUEsQ0FBQSxhQUFBLEdBQUEsRUFBQSxDQUFBLENBQ0EsSUFBQSxDQUFBLFVBQUEsUUFBQSxFQUFBO0FBQ0EsbUJBQUEsUUFBQSxDQUFBLElBQUEsQ0FBQTtTQUNBLENBQUEsQ0FBQTtLQUNBLENBQUE7O0FBR0EsV0FBQSxJQUFBLENBQUE7Q0FDQSxDQUFBLENBQUE7O0FDcENBLEdBQUEsQ0FBQSxTQUFBLENBQUEsWUFBQSxFQUFBLFlBQUE7QUFDQSxXQUFBO0FBQ0EsZ0JBQUEsRUFBQSxJQUFBO0FBQ0EsbUJBQUEsRUFBQSxtREFBQTtLQUNBLENBQUE7Q0FDQSxDQUFBLENBQUE7O0FDTEEsR0FBQSxDQUFBLFNBQUEsQ0FBQSxXQUFBLEVBQUEsWUFBQTtBQUNBLFdBQUE7QUFDQSxnQkFBQSxFQUFBLEdBQUE7QUFDQSxtQkFBQSxFQUFBLDZDQUFBO0tBQ0EsQ0FBQTtDQUNBLENBQUEsQ0FBQTs7QUNMQSxHQUFBLENBQUEsU0FBQSxDQUFBLFFBQUEsRUFBQSxVQUFBLFVBQUEsRUFBQSxXQUFBLEVBQUEsV0FBQSxFQUFBLE1BQUEsRUFBQTs7QUFFQSxXQUFBO0FBQ0EsZ0JBQUEsRUFBQSxHQUFBO0FBQ0EsYUFBQSxFQUFBLEVBQUE7QUFDQSxtQkFBQSxFQUFBLHlDQUFBO0FBQ0EsWUFBQSxFQUFBLGNBQUEsS0FBQSxFQUFBOztBQUVBLGlCQUFBLENBQUEsS0FBQSxHQUFBLENBQ0EsRUFBQSxLQUFBLEVBQUEsUUFBQSxFQUFBLEtBQUEsRUFBQSxRQUFBLEVBQUEsRUFDQSxFQUFBLEtBQUEsRUFBQSxNQUFBLEVBQUEsS0FBQSxFQUFBLE1BQUEsRUFBQSxFQUNBLEVBQUEsS0FBQSxFQUFBLFFBQUEsRUFBQSxLQUFBLEVBQUEsUUFBQSxFQUFBLEVBQ0EsRUFBQSxLQUFBLEVBQUEsT0FBQSxFQUFBLEtBQUEsRUFBQSxPQUFBLEVBQUEsRUFDQSxFQUFBLEtBQUEsRUFBQSxlQUFBLEVBQUEsS0FBQSxFQUFBLE1BQUEsRUFBQSxDQUNBLENBQUE7O0FBRUEsaUJBQUEsQ0FBQSxJQUFBLEdBQUEsSUFBQSxDQUFBOztBQUVBLGlCQUFBLENBQUEsVUFBQSxHQUFBLFlBQUE7QUFDQSx1QkFBQSxXQUFBLENBQUEsZUFBQSxFQUFBLENBQUE7YUFDQSxDQUFBOztBQUVBLGlCQUFBLENBQUEsTUFBQSxHQUFBLFlBQUE7QUFDQSwyQkFBQSxDQUFBLE1BQUEsRUFBQSxDQUFBLElBQUEsQ0FBQSxZQUFBO0FBQ0EsMEJBQUEsQ0FBQSxFQUFBLENBQUEsTUFBQSxDQUFBLENBQUE7aUJBQ0EsQ0FBQSxDQUFBO2FBQ0EsQ0FBQTs7QUFFQSxnQkFBQSxPQUFBLEdBQUEsU0FBQSxPQUFBLEdBQUE7QUFDQSwyQkFBQSxDQUFBLGVBQUEsRUFBQSxDQUFBLElBQUEsQ0FBQSxVQUFBLElBQUEsRUFBQTtBQUNBLHlCQUFBLENBQUEsSUFBQSxHQUFBLElBQUEsQ0FBQTtpQkFDQSxDQUFBLENBQUE7YUFDQSxDQUFBOztBQUVBLGdCQUFBLFVBQUEsR0FBQSxTQUFBLFVBQUEsR0FBQTtBQUNBLHFCQUFBLENBQUEsSUFBQSxHQUFBLElBQUEsQ0FBQTthQUNBLENBQUE7O0FBRUEsbUJBQUEsRUFBQSxDQUFBOztBQUVBLHNCQUFBLENBQUEsR0FBQSxDQUFBLFdBQUEsQ0FBQSxZQUFBLEVBQUEsT0FBQSxDQUFBLENBQUE7QUFDQSxzQkFBQSxDQUFBLEdBQUEsQ0FBQSxXQUFBLENBQUEsYUFBQSxFQUFBLE9BQUEsQ0FBQSxDQUFBO0FBQ0Esc0JBQUEsQ0FBQSxHQUFBLENBQUEsV0FBQSxDQUFBLGFBQUEsRUFBQSxVQUFBLENBQUEsQ0FBQTtBQUNBLHNCQUFBLENBQUEsR0FBQSxDQUFBLFdBQUEsQ0FBQSxjQUFBLEVBQUEsVUFBQSxDQUFBLENBQUE7U0FFQTs7S0FFQSxDQUFBO0NBRUEsQ0FBQSxDQUFBOztBQ2pEQSxHQUFBLENBQUEsU0FBQSxDQUFBLGdCQUFBLEVBQUEsWUFBQTtBQUNBLFdBQUE7QUFDQSxnQkFBQSxFQUFBLElBQUE7QUFDQSxtQkFBQSxFQUFBLDZEQUFBO0tBQ0EsQ0FBQTtDQUNBLENBQUEsQ0FBQTs7QUNMQSxHQUFBLENBQUEsU0FBQSxDQUFBLFlBQUEsRUFBQSxVQUFBLFdBQUEsRUFBQSxZQUFBLEVBQUEsTUFBQSxFQUFBLE9BQUEsRUFBQTtBQUNBLFdBQUE7QUFDQSxnQkFBQSxFQUFBLEdBQUE7QUFDQSxtQkFBQSxFQUFBLHlEQUFBO0FBQ0EsWUFBQSxFQUFBLGNBQUEsS0FBQSxFQUFBO0FBQ0EsaUJBQUEsQ0FBQSxRQUFBLEdBQUEsSUFBQSxDQUFBO0FBQ0EsaUJBQUEsQ0FBQSxPQUFBLEdBQUEsT0FBQSxDQUFBLElBQUEsQ0FBQSxPQUFBLENBQUE7QUFDQSxpQkFBQSxDQUFBLFFBQUEsR0FBQSxLQUFBLENBQUE7QUFDQSxpQkFBQSxDQUFBLFFBQUEsR0FBQSxLQUFBLENBQUE7OztBQUdBLGdCQUFBLEtBQUEsQ0FBQSxJQUFBLEdBQUEsT0FBQSxDQUFBLElBQUEsRUFBQSxLQUFBLENBQUEsT0FBQSxHQUFBLElBQUEsQ0FBQTs7QUFFQSxpQkFBQSxDQUFBLFVBQUEsR0FBQSxZQUFBO0FBQ0EscUJBQUEsQ0FBQSxNQUFBLEdBQUEsT0FBQSxDQUFBLElBQUEsQ0FBQSxLQUFBLENBQUEsSUFBQSxDQUFBLENBQUE7QUFDQSxxQkFBQSxDQUFBLFFBQUEsR0FBQSxJQUFBLENBQUE7YUFDQSxDQUFBO0FBQ0EsaUJBQUEsQ0FBQSxVQUFBLEdBQUEsWUFBQTtBQUNBLHFCQUFBLENBQUEsSUFBQSxHQUFBLE9BQUEsQ0FBQSxJQUFBLENBQUEsS0FBQSxDQUFBLE1BQUEsQ0FBQSxDQUFBO0FBQ0EscUJBQUEsQ0FBQSxRQUFBLEdBQUEsS0FBQSxDQUFBO0FBQ0EscUJBQUEsQ0FBQSxRQUFBLEdBQUEsS0FBQSxDQUFBO2FBQ0EsQ0FBQTtBQUNBLGlCQUFBLENBQUEsUUFBQSxHQUFBLFVBQUEsSUFBQSxFQUFBO0FBQ0EsMkJBQUEsQ0FBQSxJQUFBLENBQUEsSUFBQSxDQUFBLEdBQUEsRUFBQSxJQUFBLENBQUEsQ0FDQSxJQUFBLENBQUEsVUFBQSxXQUFBLEVBQUE7QUFDQSx5QkFBQSxDQUFBLElBQUEsR0FBQSxXQUFBLENBQUE7QUFDQSx5QkFBQSxDQUFBLFFBQUEsR0FBQSxLQUFBLENBQUE7QUFDQSx5QkFBQSxDQUFBLFFBQUEsR0FBQSxLQUFBLENBQUE7aUJBQ0EsQ0FBQSxDQUFBO2FBQ0EsQ0FBQTtBQUNBLGlCQUFBLENBQUEsVUFBQSxHQUFBLFVBQUEsSUFBQSxFQUFBO0FBQ0EsMkJBQUEsVUFBQSxDQUFBLElBQUEsQ0FBQSxDQUNBLElBQUEsQ0FBQSxZQUFBO0FBQ0EseUJBQUEsQ0FBQSxRQUFBLEdBQUEsS0FBQSxDQUFBO0FBQ0EseUJBQUEsQ0FBQSxRQUFBLEdBQUEsS0FBQSxDQUFBO0FBQ0EsMEJBQUEsQ0FBQSxFQUFBLENBQUEsTUFBQSxDQUFBLENBQUE7aUJBQ0EsQ0FBQSxDQUFBO2FBQ0EsQ0FBQTs7QUFFQSxpQkFBQSxDQUFBLFlBQUEsR0FBQSxZQUFBOzs7Ozs7QUFNQSxxQkFBQSxDQUFBLE1BQUEsR0FBQSxPQUFBLENBQUEsSUFBQSxDQUFBLEtBQUEsQ0FBQSxJQUFBLENBQUEsQ0FBQTtBQUNBLHFCQUFBLENBQUEsUUFBQSxHQUFBLElBQUEsQ0FBQTthQUNBLENBQUE7U0FDQTtBQUNBLGFBQUEsRUFBQTtBQUNBLGdCQUFBLEVBQUEsR0FBQTtTQUNBO0tBQ0EsQ0FBQTtDQUNBLENBQUEsQ0FBQTs7QUNyREEsR0FBQSxDQUFBLFNBQUEsQ0FBQSxVQUFBLEVBQUEsWUFBQTtBQUNBLFdBQUE7QUFDQSxnQkFBQSxFQUFBLEdBQUE7QUFDQSxtQkFBQSxFQUFBLHFEQUFBO0tBQ0EsQ0FBQTtDQUNBLENBQUEsQ0FBQSIsImZpbGUiOiJtYWluLmpzIiwic291cmNlc0NvbnRlbnQiOlsiJ3VzZSBzdHJpY3QnO1xud2luZG93LmFwcCA9IGFuZ3VsYXIubW9kdWxlKCdNU0ZUZW1wJywgWyd1aS5yb3V0ZXInLCAndWkuYm9vdHN0cmFwJywgJ2ZzYVByZUJ1aWx0J10pO1xuXG5hcHAuY29uZmlnKGZ1bmN0aW9uICgkdXJsUm91dGVyUHJvdmlkZXIsICRsb2NhdGlvblByb3ZpZGVyKSB7XG5cblx0Ly8gdGhpcyBtYWtlcyB0aGUgJy91c2Vycy8nIHJvdXRlIGNvcnJlY3RseSByZWRpcmVjdCB0byAnL3VzZXJzJ1xuXHQkdXJsUm91dGVyUHJvdmlkZXIucnVsZShmdW5jdGlvbiAoJGluamVjdG9yLCAkbG9jYXRpb24pIHtcblxuXHRcdHZhciByZSA9IC8oLispKFxcLyspKFxcPy4qKT8kL1xuXHRcdHZhciBwYXRoID0gJGxvY2F0aW9uLnVybCgpO1xuXG5cdFx0aWYocmUudGVzdChwYXRoKSkge1xuXHRcdFx0cmV0dXJuIHBhdGgucmVwbGFjZShyZSwgJyQxJDMnKVxuXHRcdH1cblxuXHRcdHJldHVybiBmYWxzZTtcblx0fSk7XG5cdC8vIFRoaXMgdHVybnMgb2ZmIGhhc2hiYW5nIHVybHMgKC8jYWJvdXQpIGFuZCBjaGFuZ2VzIGl0IHRvIHNvbWV0aGluZyBub3JtYWwgKC9hYm91dClcblx0JGxvY2F0aW9uUHJvdmlkZXIuaHRtbDVNb2RlKHRydWUpO1xuXHQkdXJsUm91dGVyUHJvdmlkZXIud2hlbignL2F1dGgvOnByb3ZpZGVyJywgZnVuY3Rpb24gKCkge1xuXHRcdHdpbmRvdy5sb2NhdGlvbi5yZWxvYWQoKTtcblx0fSk7XG5cdC8vIElmIHdlIGdvIHRvIGEgVVJMIHRoYXQgdWktcm91dGVyIGRvZXNuJ3QgaGF2ZSByZWdpc3RlcmVkLCBnbyB0byB0aGUgXCIvXCIgdXJsLlxuXHQkdXJsUm91dGVyUHJvdmlkZXIub3RoZXJ3aXNlKCcvJyk7XG5cbn0pO1xuXG4vLyBUaGlzIGFwcC5ydW4gaXMgZm9yIGNvbnRyb2xsaW5nIGFjY2VzcyB0byBzcGVjaWZpYyBzdGF0ZXMuXG5hcHAucnVuKGZ1bmN0aW9uICgkcm9vdFNjb3BlLCBBdXRoU2VydmljZSwgJHN0YXRlKSB7XG5cblx0Ly8gVGhlIGdpdmVuIHN0YXRlIHJlcXVpcmVzIGFuIGF1dGhlbnRpY2F0ZWQgdXNlci5cblx0dmFyIGRlc3RpbmF0aW9uU3RhdGVSZXF1aXJlc0F1dGggPSBmdW5jdGlvbiAoc3RhdGUpIHtcblx0XHRyZXR1cm4gc3RhdGUuZGF0YSAmJiBzdGF0ZS5kYXRhLmF1dGhlbnRpY2F0ZTtcblx0fTtcblxuXHQvLyAkc3RhdGVDaGFuZ2VTdGFydCBpcyBhbiBldmVudCBmaXJlZFxuXHQvLyB3aGVuZXZlciB0aGUgcHJvY2VzcyBvZiBjaGFuZ2luZyBhIHN0YXRlIGJlZ2lucy5cblx0JHJvb3RTY29wZS4kb24oJyRzdGF0ZUNoYW5nZVN0YXJ0JywgZnVuY3Rpb24gKGV2ZW50LCB0b1N0YXRlLCB0b1BhcmFtcykge1xuXG5cdFx0aWYgKCFkZXN0aW5hdGlvblN0YXRlUmVxdWlyZXNBdXRoKHRvU3RhdGUpKSB7XG5cdFx0XHQvLyBUaGUgZGVzdGluYXRpb24gc3RhdGUgZG9lcyBub3QgcmVxdWlyZSBhdXRoZW50aWNhdGlvblxuXHRcdFx0Ly8gU2hvcnQgY2lyY3VpdCB3aXRoIHJldHVybi5cblx0XHRcdHJldHVybjtcblx0XHR9XG5cblx0XHRpZiAoQXV0aFNlcnZpY2UuaXNBdXRoZW50aWNhdGVkKCkpIHtcblx0XHRcdC8vIFRoZSB1c2VyIGlzIGF1dGhlbnRpY2F0ZWQuXG5cdFx0XHQvLyBTaG9ydCBjaXJjdWl0IHdpdGggcmV0dXJuLlxuXHRcdFx0cmV0dXJuO1xuXHRcdH1cblxuXHRcdC8vIENhbmNlbCBuYXZpZ2F0aW5nIHRvIG5ldyBzdGF0ZS5cblx0XHRldmVudC5wcmV2ZW50RGVmYXVsdCgpO1xuXG5cdFx0QXV0aFNlcnZpY2UuZ2V0TG9nZ2VkSW5Vc2VyKCkudGhlbihmdW5jdGlvbiAodXNlcikge1xuXHRcdFx0Ly8gSWYgYSB1c2VyIGlzIHJldHJpZXZlZCwgdGhlbiByZW5hdmlnYXRlIHRvIHRoZSBkZXN0aW5hdGlvblxuXHRcdFx0Ly8gKHRoZSBzZWNvbmQgdGltZSwgQXV0aFNlcnZpY2UuaXNBdXRoZW50aWNhdGVkKCkgd2lsbCB3b3JrKVxuXHRcdFx0Ly8gb3RoZXJ3aXNlLCBpZiBubyB1c2VyIGlzIGxvZ2dlZCBpbiwgZ28gdG8gXCJsb2dpblwiIHN0YXRlLlxuXHRcdFx0aWYgKHVzZXIpIHtcblx0XHRcdFx0JHN0YXRlLmdvKHRvU3RhdGUubmFtZSwgdG9QYXJhbXMpO1xuXHRcdFx0fSBlbHNlIHtcblx0XHRcdFx0JHN0YXRlLmdvKCdsb2dpbicpO1xuXHRcdFx0fVxuXHRcdH0pO1xuXG5cdH0pO1xuXG59KTtcbiIsImFwcC5jb25maWcoZnVuY3Rpb24gKCRzdGF0ZVByb3ZpZGVyKSB7XG4gICAgJHN0YXRlUHJvdmlkZXIuc3RhdGUoJ2FsZXJ0cycsIHtcbiAgICAgICAgdXJsOiAnL2FsZXJ0cycsXG4gICAgICAgIHRlbXBsYXRlVXJsOiAnanMvYWxlcnRzL2FsZXJ0cy5odG1sJyxcbiAgICAgICAgY29udHJvbGxlcjogJ2FsZXJ0Q3RybCdcbiAgICB9KVxufSlcblxuYXBwLmNvbnRyb2xsZXIoJ2FsZXJ0Q3RybCcsIGZ1bmN0aW9uIChEd2VldEZhY3RvcnksICRzY29wZSwgJHN0YXRlLCAkcm9vdFNjb3BlKSB7XG5cbiAgICAkc2NvcGUuc2F2ZUFsZXJ0ID0gZnVuY3Rpb24gKGFsZXJ0KSB7XG4gICAgICAgIGFsZXJ0LnVwcGVyQm91bmQgPSBOdW1iZXIoYWxlcnQudXBwZXJCb3VuZCk7XG4gICAgICAgIGFsZXJ0Lmxvd2VyQm91bmQgPSBOdW1iZXIoYWxlcnQubG93ZXJCb3VuZCk7XG4gICAgICAgIGFsZXJ0LnRlbXA7XG4gICAgICAgICRyb290U2NvcGUuYWxlcnQgPSBhbGVydDtcbiAgICAgICAgJHJvb3RTY29wZS5hbGVydEVudGVyZWQgPSB0cnVlO1xuICAgICAgICAkc3RhdGUuZ28oJ2hvbWUnKTtcbiAgICB9XG59KVxuIiwiYXBwLmNvbmZpZyhmdW5jdGlvbiAoJHN0YXRlUHJvdmlkZXIpIHtcbiAgICAkc3RhdGVQcm92aWRlclxuICAgIC5zdGF0ZSgnZGF0YScsIHtcbiAgICAgICAgdXJsOiAnL2RhdGEnLFxuICAgICAgICB0ZW1wbGF0ZVVybDogJ2pzL2RhdGEvZGF0YS5odG1sJyxcbiAgICAgICAgY29udHJvbGxlcjogZnVuY3Rpb24gKCRzY29wZSwgYWxsRHdlZXRzKSB7XG4gICAgICAgICAgJHNjb3BlLmR3ZWV0cyA9IGFsbER3ZWV0cztcbiAgICAgICAgfSxcbiAgICAgICAgcmVzb2x2ZToge1xuICAgICAgICAgICAgLy8gZmluZER3ZWV0czogZnVuY3Rpb24gKER3ZWV0RmFjdG9yeSkge1xuICAgICAgICAgICAgLy8gICAgIHJldHVybiBEd2VldEZhY3RvcnkuZ2V0QWxsKCk7XG4gICAgICAgICAgICAvLyB9O1xuICAgICAgICAgICAgYWxsRHdlZXRzOiBmdW5jdGlvbiAoRHdlZXRGYWN0b3J5KSB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIER3ZWV0RmFjdG9yeS5nZXRBbGwoKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgIH0pXG59KTtcbiIsImFwcC5jb25maWcoZnVuY3Rpb24gKCRzdGF0ZVByb3ZpZGVyKSB7XG4gICAgJHN0YXRlUHJvdmlkZXIuc3RhdGUoJ2RvY3MnLCB7XG4gICAgICAgIHVybDogJy9kb2NzJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6ICdqcy9kb2NzL2RvY3MuaHRtbCdcbiAgICB9KTtcbn0pO1xuIiwiKGZ1bmN0aW9uICgpIHtcblxuICAgICd1c2Ugc3RyaWN0JztcblxuICAgIC8vIEhvcGUgeW91IGRpZG4ndCBmb3JnZXQgQW5ndWxhciEgRHVoLWRveS5cbiAgICBpZiAoIXdpbmRvdy5hbmd1bGFyKSB0aHJvdyBuZXcgRXJyb3IoJ0kgY2FuXFwndCBmaW5kIEFuZ3VsYXIhJyk7XG5cbiAgICB2YXIgYXBwID0gYW5ndWxhci5tb2R1bGUoJ2ZzYVByZUJ1aWx0JywgW10pO1xuXG4gICAgYXBwLmZhY3RvcnkoJ1NvY2tldCcsIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgaWYgKCF3aW5kb3cuaW8pIHRocm93IG5ldyBFcnJvcignc29ja2V0LmlvIG5vdCBmb3VuZCEnKTtcbiAgICAgICAgcmV0dXJuIHdpbmRvdy5pbyh3aW5kb3cubG9jYXRpb24ub3JpZ2luKTtcbiAgICB9KTtcblxuICAgIC8vIEFVVEhfRVZFTlRTIGlzIHVzZWQgdGhyb3VnaG91dCBvdXIgYXBwIHRvXG4gICAgLy8gYnJvYWRjYXN0IGFuZCBsaXN0ZW4gZnJvbSBhbmQgdG8gdGhlICRyb290U2NvcGVcbiAgICAvLyBmb3IgaW1wb3J0YW50IGV2ZW50cyBhYm91dCBhdXRoZW50aWNhdGlvbiBmbG93LlxuICAgIGFwcC5jb25zdGFudCgnQVVUSF9FVkVOVFMnLCB7XG4gICAgICAgIGxvZ2luU3VjY2VzczogJ2F1dGgtbG9naW4tc3VjY2VzcycsXG4gICAgICAgIGxvZ2luRmFpbGVkOiAnYXV0aC1sb2dpbi1mYWlsZWQnLFxuICAgICAgICBzaWdudXBTdWNjZXNzOiAnYXV0aC1zaWdudXAtc3VjY2VzcycsXG4gICAgICAgIHNpZ251cEZhaWxlZDogJ2F1dGgtc2lnbnVwLWZhaWxlZCcsXG4gICAgICAgIGxvZ291dFN1Y2Nlc3M6ICdhdXRoLWxvZ291dC1zdWNjZXNzJyxcbiAgICAgICAgc2Vzc2lvblRpbWVvdXQ6ICdhdXRoLXNlc3Npb24tdGltZW91dCcsXG4gICAgICAgIG5vdEF1dGhlbnRpY2F0ZWQ6ICdhdXRoLW5vdC1hdXRoZW50aWNhdGVkJyxcbiAgICAgICAgbm90QXV0aG9yaXplZDogJ2F1dGgtbm90LWF1dGhvcml6ZWQnXG4gICAgfSk7XG5cbiAgICBhcHAuZmFjdG9yeSgnQXV0aEludGVyY2VwdG9yJywgZnVuY3Rpb24gKCRyb290U2NvcGUsICRxLCBBVVRIX0VWRU5UUykge1xuICAgICAgICB2YXIgc3RhdHVzRGljdCA9IHtcbiAgICAgICAgICAgIDQwMTogQVVUSF9FVkVOVFMubm90QXV0aGVudGljYXRlZCxcbiAgICAgICAgICAgIDQwMzogQVVUSF9FVkVOVFMubm90QXV0aG9yaXplZCxcbiAgICAgICAgICAgIDQxOTogQVVUSF9FVkVOVFMuc2Vzc2lvblRpbWVvdXQsXG4gICAgICAgICAgICA0NDA6IEFVVEhfRVZFTlRTLnNlc3Npb25UaW1lb3V0XG4gICAgICAgIH07XG4gICAgICAgIHJldHVybiB7XG4gICAgICAgICAgICByZXNwb25zZUVycm9yOiBmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgICAgICAgICAkcm9vdFNjb3BlLiRicm9hZGNhc3Qoc3RhdHVzRGljdFtyZXNwb25zZS5zdGF0dXNdLCByZXNwb25zZSk7XG4gICAgICAgICAgICAgICAgcmV0dXJuICRxLnJlamVjdChyZXNwb25zZSlcbiAgICAgICAgICAgIH1cbiAgICAgICAgfTtcbiAgICB9KTtcblxuICAgIGFwcC5jb25maWcoZnVuY3Rpb24gKCRodHRwUHJvdmlkZXIpIHtcbiAgICAgICAgJGh0dHBQcm92aWRlci5pbnRlcmNlcHRvcnMucHVzaChbXG4gICAgICAgICAgICAnJGluamVjdG9yJyxcbiAgICAgICAgICAgIGZ1bmN0aW9uICgkaW5qZWN0b3IpIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gJGluamVjdG9yLmdldCgnQXV0aEludGVyY2VwdG9yJyk7XG4gICAgICAgICAgICB9XG4gICAgICAgIF0pO1xuICAgIH0pO1xuXG4gICAgYXBwLnNlcnZpY2UoJ0F1dGhTZXJ2aWNlJywgZnVuY3Rpb24gKCRodHRwLCBTZXNzaW9uLCAkcm9vdFNjb3BlLCBBVVRIX0VWRU5UUywgJHEpIHtcblxuICAgICAgICBmdW5jdGlvbiBvblN1Y2Nlc3NmdWxMb2dpbihyZXNwb25zZSkge1xuICAgICAgICAgICAgdmFyIGRhdGEgPSByZXNwb25zZS5kYXRhO1xuICAgICAgICAgICAgU2Vzc2lvbi5jcmVhdGUoZGF0YS5pZCwgZGF0YS51c2VyKTtcbiAgICAgICAgICAgICRyb290U2NvcGUuJGJyb2FkY2FzdChBVVRIX0VWRU5UUy5sb2dpblN1Y2Nlc3MpO1xuICAgICAgICAgICAgcmV0dXJuIGRhdGEudXNlcjtcbiAgICAgICAgfVxuXG4gICAgICAgIC8vYWRkIHN1Y2Nlc3NmdWwgc2lnbnVwXG4gICAgICAgIGZ1bmN0aW9uIG9uU3VjY2Vzc2Z1bFNpZ251cChyZXNwb25zZSkge1xuICAgICAgICAgICAgdmFyIGRhdGEgPSByZXNwb25zZS5kYXRhO1xuICAgICAgICAgICAgU2Vzc2lvbi5jcmVhdGUoZGF0YS5pZCwgZGF0YS51c2VyKTtcbiAgICAgICAgICAgICRyb290U2NvcGUuJGJyb2FkY2FzdChBVVRIX0VWRU5UUy5zaWdudXBTdWNjZXNzKTtcbiAgICAgICAgICAgIHJldHVybiBkYXRhLnVzZXI7XG4gICAgICAgIH1cblxuICAgICAgICAvLyBVc2VzIHRoZSBzZXNzaW9uIGZhY3RvcnkgdG8gc2VlIGlmIGFuXG4gICAgICAgIC8vIGF1dGhlbnRpY2F0ZWQgdXNlciBpcyBjdXJyZW50bHkgcmVnaXN0ZXJlZC5cbiAgICAgICAgdGhpcy5pc0F1dGhlbnRpY2F0ZWQgPSBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICByZXR1cm4gISFTZXNzaW9uLnVzZXI7XG4gICAgICAgIH07XG5cbiAgICAgICAgdGhpcy5nZXRMb2dnZWRJblVzZXIgPSBmdW5jdGlvbiAoZnJvbVNlcnZlcikge1xuXG4gICAgICAgICAgICAvLyBJZiBhbiBhdXRoZW50aWNhdGVkIHNlc3Npb24gZXhpc3RzLCB3ZVxuICAgICAgICAgICAgLy8gcmV0dXJuIHRoZSB1c2VyIGF0dGFjaGVkIHRvIHRoYXQgc2Vzc2lvblxuICAgICAgICAgICAgLy8gd2l0aCBhIHByb21pc2UuIFRoaXMgZW5zdXJlcyB0aGF0IHdlIGNhblxuICAgICAgICAgICAgLy8gYWx3YXlzIGludGVyZmFjZSB3aXRoIHRoaXMgbWV0aG9kIGFzeW5jaHJvbm91c2x5LlxuXG4gICAgICAgICAgICAvLyBPcHRpb25hbGx5LCBpZiB0cnVlIGlzIGdpdmVuIGFzIHRoZSBmcm9tU2VydmVyIHBhcmFtZXRlcixcbiAgICAgICAgICAgIC8vIHRoZW4gdGhpcyBjYWNoZWQgdmFsdWUgd2lsbCBub3QgYmUgdXNlZC5cblxuICAgICAgICAgICAgaWYgKHRoaXMuaXNBdXRoZW50aWNhdGVkKCkgJiYgZnJvbVNlcnZlciAhPT0gdHJ1ZSkge1xuICAgICAgICAgICAgICAgIHJldHVybiAkcS53aGVuKFNlc3Npb24udXNlcik7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIC8vIE1ha2UgcmVxdWVzdCBHRVQgL3Nlc3Npb24uXG4gICAgICAgICAgICAvLyBJZiBpdCByZXR1cm5zIGEgdXNlciwgY2FsbCBvblN1Y2Nlc3NmdWxMb2dpbiB3aXRoIHRoZSByZXNwb25zZS5cbiAgICAgICAgICAgIC8vIElmIGl0IHJldHVybnMgYSA0MDEgcmVzcG9uc2UsIHdlIGNhdGNoIGl0IGFuZCBpbnN0ZWFkIHJlc29sdmUgdG8gbnVsbC5cbiAgICAgICAgICAgIHJldHVybiAkaHR0cC5nZXQoJy9zZXNzaW9uJykudGhlbihvblN1Y2Nlc3NmdWxMb2dpbikuY2F0Y2goZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgIHJldHVybiBudWxsO1xuICAgICAgICAgICAgfSk7XG5cbiAgICAgICAgfTtcblxuICAgICAgICB0aGlzLmxvZ2luID0gZnVuY3Rpb24gKGNyZWRlbnRpYWxzKSB7XG4gICAgICAgICAgICByZXR1cm4gJGh0dHAucG9zdCgnL2xvZ2luJywgY3JlZGVudGlhbHMpXG4gICAgICAgICAgICAgICAgLnRoZW4ob25TdWNjZXNzZnVsTG9naW4pXG4gICAgICAgICAgICAgICAgLmNhdGNoKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuICRxLnJlamVjdCh7IG1lc3NhZ2U6ICdJbnZhbGlkIGxvZ2luIGNyZWRlbnRpYWxzLicgfSk7XG4gICAgICAgICAgICAgICAgfSk7XG4gICAgICAgIH07XG5cbiAgICAgICAgdGhpcy5sb2dvdXQgPSBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICByZXR1cm4gJGh0dHAuZ2V0KCcvbG9nb3V0JykudGhlbihmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAgICAgU2Vzc2lvbi5kZXN0cm95KCk7XG4gICAgICAgICAgICAgICAgJHJvb3RTY29wZS4kYnJvYWRjYXN0KEFVVEhfRVZFTlRTLmxvZ291dFN1Y2Nlc3MpO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgIH07XG5cbiAgICAgICAgdGhpcy5zaWdudXAgPSBmdW5jdGlvbiAoY3JlZGVudGlhbHMpIHtcbiAgICAgICAgICAgIHJldHVybiAkaHR0cC5wb3N0KCcvc2lnbnVwJywgY3JlZGVudGlhbHMpXG4gICAgICAgICAgICAgICAgLnRoZW4ob25TdWNjZXNzZnVsU2lnbnVwKTtcbiAgICAgICAgfTtcblxuXG4gICAgfSk7XG5cbiAgICBhcHAuc2VydmljZSgnU2Vzc2lvbicsIGZ1bmN0aW9uICgkcm9vdFNjb3BlLCBBVVRIX0VWRU5UUykge1xuXG4gICAgICAgIHZhciBzZWxmID0gdGhpcztcblxuICAgICAgICAkcm9vdFNjb3BlLiRvbihBVVRIX0VWRU5UUy5ub3RBdXRoZW50aWNhdGVkLCBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICBzZWxmLmRlc3Ryb3koKTtcbiAgICAgICAgfSk7XG5cbiAgICAgICAgJHJvb3RTY29wZS4kb24oQVVUSF9FVkVOVFMuc2Vzc2lvblRpbWVvdXQsIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgIHNlbGYuZGVzdHJveSgpO1xuICAgICAgICB9KTtcblxuICAgICAgICB0aGlzLmlkID0gbnVsbDtcbiAgICAgICAgdGhpcy51c2VyID0gbnVsbDtcblxuICAgICAgICB0aGlzLmNyZWF0ZSA9IGZ1bmN0aW9uIChzZXNzaW9uSWQsIHVzZXIpIHtcbiAgICAgICAgICAgIHRoaXMuaWQgPSBzZXNzaW9uSWQ7XG4gICAgICAgICAgICB0aGlzLnVzZXIgPSB1c2VyO1xuICAgICAgICB9O1xuXG4gICAgICAgIHRoaXMuZGVzdHJveSA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgIHRoaXMuaWQgPSBudWxsO1xuICAgICAgICAgICAgdGhpcy51c2VyID0gbnVsbDtcbiAgICAgICAgfTtcblxuICAgIH0pO1xuXG59KSgpO1xuIiwiYXBwLmNvbmZpZyhmdW5jdGlvbigkc3RhdGVQcm92aWRlcikge1xuICAgICRzdGF0ZVByb3ZpZGVyLnN0YXRlKCdob21lJywge1xuICAgICAgICB1cmw6ICcvJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6ICdqcy9ob21lL2hvbWUuaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6IGZ1bmN0aW9uKCRzY29wZSwgRHdlZXRGYWN0b3J5LCBsYXRlc3RUZW1wLCAkcm9vdFNjb3BlKSB7XG4gICAgICAgICAgICAvL0NyZWF0ZSBhcnJheSBvZiBsYXRlc3QgZHdlZXRzIHRvIGRpc3BsYXkgb24gaG9tZSBzdGF0ZVxuICAgICAgICAgICAgJHNjb3BlLmhvbWVEd2VldHMgPSBbXTtcbiAgICAgICAgICAgICRyb290U2NvcGUuaG9tZUFsZXJ0cyA9IFtdO1xuXG4gICAgICAgICAgICAkc2NvcGUuZXJyb3IgPSBudWxsO1xuXG4gICAgICAgICAgICAvL0luaXRpYWxpemUgd2l0aCBmaXJzdCBkd2VldFxuICAgICAgICAgICAgRHdlZXRGYWN0b3J5LmdldExhdGVzdCgpXG4gICAgICAgICAgICAudGhlbihmdW5jdGlvbihkd2VldCl7XG4gICAgICAgICAgICAgICAgJHNjb3BlLnByZXZEd2VldCA9IGR3ZWV0O1xuICAgICAgICAgICAgfSk7XG5cbiAgICAgICAgICAgIC8vIGNvbnNvbGUubG9nKCRyb290U2NvcGUuYWxlcnQpXG5cbiAgICAgICAgICAgIHZhciBsaW5lMSA9IG5ldyBUaW1lU2VyaWVzKCk7XG4gICAgICAgICAgICB2YXIgbGluZTIgPSBuZXcgVGltZVNlcmllcygpO1xuXG4gICAgICAgICAgICAvLyBDaGVjayBldmVyeSBoYWxmIHNlY29uZCB0byBzZWUgaWYgdGhlIGxhc3QgZHdlZXQgaXMgbmV3LCB0aGVuIHB1c2ggdG8gaG9tZUR3ZWV0cywgdGhlbiBwbG90XG4gICAgICAgICAgICBpZiAoJHJvb3RTY29wZS5hbGVydCkge1xuICAgICAgICAgICAgICAgIHNldEludGVydmFsKGZ1bmN0aW9uKCkge1xuICAgICAgICAgICAgICAgICAgICBEd2VldEZhY3RvcnkuZ2V0TGF0ZXN0KClcbiAgICAgICAgICAgICAgICAgICAgLnRoZW4oZnVuY3Rpb24oZHdlZXQpe1xuICAgICAgICAgICAgICAgICAgICAgICAgJHNjb3BlLmxhc3REd2VldCA9IGR3ZWV0O1xuICAgICAgICAgICAgICAgICAgICB9KVxuICAgICAgICAgICAgICAgICAgICAudGhlbihmdW5jdGlvbigpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHZhciByYW5kb21UZW1wID0gTWF0aC5yYW5kb20oKSo1KzcwO1xuICAgICAgICAgICAgICAgICAgICAgICAgaWYgKCRzY29wZS5wcmV2RHdlZXQuY3JlYXRlZCAhPSAkc2NvcGUubGFzdER3ZWV0LmNyZWF0ZWQpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAkc2NvcGUuaG9tZUR3ZWV0cy5wdXNoKCRzY29wZS5sYXN0RHdlZXQpO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICRzY29wZS5wcmV2RHdlZXQgPSAkc2NvcGUubGFzdER3ZWV0O1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGxpbmUxLmFwcGVuZChuZXcgRGF0ZSgpLmdldFRpbWUoKSwgJHNjb3BlLmxhc3REd2VldC5jb250ZW50WydUZW1wZXJhdHVyZSddKTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAvL1JhbmRvbSBwbG90IHRvIGNoZWNrIHRoYXQgdGhlIGdyYXBoIGlzIHdvcmtpbmdcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBsaW5lMi5hcHBlbmQobmV3IERhdGUoKS5nZXRUaW1lKCksIHJhbmRvbVRlbXApO1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgLy9EZXRlY3QgaWYgdGhlIHRlbXBlcmF0dXJlIGJyZWFrcyBvdXQgb2Ygc2FmZSByYW5nZVxuICAgICAgICAgICAgICAgICAgICAgICAgaWYgKCRzY29wZS5sYXN0RHdlZXQuY29udGVudFsnVGVtcGVyYXR1cmUnXSA+ICRyb290U2NvcGUuYWxlcnQudXBwZXJCb3VuZCB8fCAkc2NvcGUubGFzdER3ZWV0LmNvbnRlbnRbJ1RlbXBlcmF0dXJlJ10gPCAkcm9vdFNjb3BlLmFsZXJ0Lmxvd2VyQm91bmQpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb25zb2xlLmxvZygnYnJlYWsgaW4gY29sZCBjaGFpbicpXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyIGN1cnJEYXRlID0gbmV3IERhdGUoKTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YXIgY3VyclRpbWUgPSBjdXJyRGF0ZS50b1N0cmluZygpLnNsaWNlKDE2KTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAkcm9vdFNjb3BlLmFsZXJ0LnRpbWUgPSBjdXJyVGltZTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAkcm9vdFNjb3BlLmFsZXJ0LnRlbXAgPSAkc2NvcGUubGFzdER3ZWV0LmNvbnRlbnRbJ1RlbXBlcmF0dXJlJ107XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgRHdlZXRGYWN0b3J5LnBvc3RBbGVydCgkcm9vdFNjb3BlLmFsZXJ0KVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIC50aGVuIChmdW5jdGlvbiAocG9zdGVkQWxlcnQpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgJHJvb3RTY29wZS5ob21lQWxlcnRzLnB1c2gocG9zdGVkQWxlcnQpO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAkc2NvcGUuZXJyb3IgPSAnQnJlYWsgaW4gY29sZCBjaGFpbiBkZXRlY3RlZCEhJ1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0pXG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICAvL0RldGVjdCBpZiB0aGUgdGVtcGVyYXR1cmUgYnJlYWtzIG91dCBvZiBzYWZlIHJhbmdlXG4gICAgICAgICAgICAvL1RVUk4gT04gVE8gREVNT05TVFJBVEUgQlJFQUsgSU4gQ09MRCBDSEFJTiBBTEVSVCAmIEVNQUlMIEZFQVRVUkVcbiAgICAgICAgICAgICAgICAgICAgICAgIGlmIChyYW5kb21UZW1wID4gJHJvb3RTY29wZS5hbGVydC51cHBlckJvdW5kIHx8IHJhbmRvbVRlbXAgPCAkcm9vdFNjb3BlLmFsZXJ0Lmxvd2VyQm91bmQpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb25zb2xlLmxvZygnYnJlYWsgaW4gY29sZCBjaGFpbiAyJyk7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyIGN1cnJEYXRlID0gbmV3IERhdGUoKTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YXIgY3VyclRpbWUgPSBjdXJyRGF0ZS50b1N0cmluZygpLnNsaWNlKDE2KTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAkcm9vdFNjb3BlLmFsZXJ0LnRpbWUgPSBjdXJyVGltZTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAkcm9vdFNjb3BlLmFsZXJ0LnRlbXAgPSByYW5kb21UZW1wO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIER3ZWV0RmFjdG9yeS5wb3N0QWxlcnQoJHJvb3RTY29wZS5hbGVydClcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAudGhlbiAoZnVuY3Rpb24gKHBvc3RlZEFsZXJ0KSB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICRyb290U2NvcGUuaG9tZUFsZXJ0cy5wdXNoKHBvc3RlZEFsZXJ0KTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgJHNjb3BlLmVycm9yID0gJ0JyZWFrIGluIGNvbGQgY2hhaW4gZGV0ZWN0ZWQhISdcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9KVxuICAgICAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgICAgICB3aGlsZSgkc2NvcGUuaG9tZUR3ZWV0cy5sZW5ndGggPiAxMDApIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAkc2NvcGUuaG9tZUR3ZWV0cy5zaGlmdCgpO1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgd2hpbGUoJHNjb3BlLmhvbWVBbGVydHMubGVuZ3RoID4gMTAwKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgJHNjb3BlLmhvbWVBbGVydHMuc2hpZnQoKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgfSlcbiAgICAgICAgICAgICAgICB9LCA1MDApO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAvL01ha2UgYSBzbW9vdGhpZSBjaGFydCB3aXRoIGFlc3RoZXRpY2FsbHkgcGxlYXNpbmcgcHJvcGVydGllc1xuICAgICAgICAgICAgdmFyIHNtb290aGllID0gbmV3IFNtb290aGllQ2hhcnQoe1xuICAgICAgICAgICAgICAgIGdyaWQ6IHtcbiAgICAgICAgICAgICAgICAgICAgc3Ryb2tlU3R5bGU6ICdyZ2IoNjMsIDE2MCwgMTgyKScsXG4gICAgICAgICAgICAgICAgICAgIGZpbGxTdHlsZTogJ3JnYig0LCA1LCA5MSknLFxuICAgICAgICAgICAgICAgICAgICBsaW5lV2lkdGg6IDEsXG4gICAgICAgICAgICAgICAgICAgIG1pbGxpc1BlckxpbmU6IDUwMCxcbiAgICAgICAgICAgICAgICAgICAgdmVydGljYWxTZWN0aW9uczogNFxuICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAgbWF4VmFsdWU6ICRyb290U2NvcGUuYWxlcnQudXBwZXJCb3VuZCAqIDEuMDAzLFxuICAgICAgICAgICAgICAgIG1pblZhbHVlOiAkcm9vdFNjb3BlLmFsZXJ0Lmxvd2VyQm91bmQgKiAwLjk5NyxcbiAgICAgICAgICAgICAgICAvLyBtYXhWYWx1ZVNjYWxlOiAxLjAxLFxuICAgICAgICAgICAgICAgIC8vIG1pblZhbHVlU2NhbGU6IDEuMDIsXG4gICAgICAgICAgICAgICAgdGltZXN0YW1wRm9ybWF0dGVyOlNtb290aGllQ2hhcnQudGltZUZvcm1hdHRlcixcbiAgICAgICAgICAgICAgICAvL1RoZSByYW5nZSBvZiBhY2NlcHRhYmxlIHRlbXBlcmF0dXJlcyB2aXN1YWxpemVkXG4gICAgICAgICAgICAgICAgLy9TaG91bGQgY2hhbmdlICd2YWx1ZScgYWNjb3JkaW5nbHlcbiAgICAgICAgICAgICAgICBob3Jpem9udGFsTGluZXM6W3tcbiAgICAgICAgICAgICAgICAgICAgY29sb3I6JyM4ODAwMDAnLFxuICAgICAgICAgICAgICAgICAgICBsaW5lV2lkdGg6NSxcbiAgICAgICAgICAgICAgICAgICAgdmFsdWU6ICgkcm9vdFNjb3BlLmFsZXJ0LnVwcGVyQm91bmQgfHwgNzApXG4gICAgICAgICAgICAgICAgfSwge1xuICAgICAgICAgICAgICAgICAgICBjb2xvcjonIzg4MDAwMCcsXG4gICAgICAgICAgICAgICAgICAgIGxpbmVXaWR0aDo1LFxuICAgICAgICAgICAgICAgICAgICB2YWx1ZTogKCRyb290U2NvcGUuYWxlcnQubG93ZXJCb3VuZCB8fCA2OClcbiAgICAgICAgICAgICAgICB9XVxuICAgICAgICAgICAgfSk7XG5cbiAgICAgICAgICAgIHNtb290aGllLmFkZFRpbWVTZXJpZXMobGluZTEsIHtcbiAgICAgICAgICAgICAgICBzdHJva2VTdHlsZTogJ3JnYigwLCAyNTUsIDApJyxcbiAgICAgICAgICAgICAgICBmaWxsU3R5bGU6ICdyZ2JhKDAsIDI1NSwgMCwgMC40KScsXG4gICAgICAgICAgICAgICAgbGluZVdpZHRoOiAzXG4gICAgICAgICAgICB9KTtcbiAgICAgICAgICAgIHNtb290aGllLmFkZFRpbWVTZXJpZXMobGluZTIsIHtcbiAgICAgICAgICAgICAgICBzdHJva2VTdHlsZTogJ3JnYigyNTUsIDAsIDI1NSknLFxuICAgICAgICAgICAgICAgIGZpbGxTdHlsZTogJ3JnYmEoMjU1LCAwLCAyNTUsIDAuMyknLFxuICAgICAgICAgICAgICAgIGxpbmVXaWR0aDogM1xuICAgICAgICAgICAgfSk7XG5cbiAgICAgICAgICAgIHNtb290aGllLnN0cmVhbVRvKGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKFwiY2hhcnRcIiksIDMwMCk7XG4gICAgICAgIH0sXG4gICAgICAgIHJlc29sdmU6IHtcbiAgICAgICAgICAgIGxhdGVzdFRlbXA6IGZ1bmN0aW9uIChEd2VldEZhY3RvcnkpIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gRHdlZXRGYWN0b3J5LmdldExhdGVzdCgpXG4gICAgICAgICAgICAgICAgLnRoZW4oIGZ1bmN0aW9uIChkd2VldCkge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZHdlZXQuY29udGVudFsnVGVtcGVyYXR1cmUnXTtcbiAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgIH0pO1xufSk7XG4iLCJhcHAuY29uZmlnKGZ1bmN0aW9uKCRzdGF0ZVByb3ZpZGVyKSB7XG4gICAgJHN0YXRlUHJvdmlkZXIuc3RhdGUoJ2xhdGVzdCcsIHtcbiAgICAgICAgdXJsOiAnL2RhdGEvbGF0ZXN0JyxcbiAgICAgICAgdGVtcGxhdGVVcmw6ICdqcy9sYXRlc3QvbGF0ZXN0Lmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiBmdW5jdGlvbiAoJHNjb3BlLCBsYXRlc3REd2VldCkge1xuICAgICAgICAgICRzY29wZS5sYXRlc3REd2VldCA9IGxhdGVzdER3ZWV0O1xuICAgICAgICB9LFxuICAgICAgICByZXNvbHZlOiB7XG4gICAgICAgICAgICBsYXRlc3REd2VldDogZnVuY3Rpb24gKER3ZWV0RmFjdG9yeSkge1xuICAgICAgICAgICAgICAgIHJldHVybiBEd2VldEZhY3RvcnkuZ2V0TGF0ZXN0KCk7XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICB9KVxufSlcbiIsImFwcC5jb25maWcoZnVuY3Rpb24gKCRzdGF0ZVByb3ZpZGVyKSB7XG4gICAgJHN0YXRlUHJvdmlkZXJcbiAgICAuc3RhdGUoJ3Jlc2V0UGFzcycsIHtcbiAgICAgICAgdXJsOiAnL3Jlc2V0Lzp1c2VySWQnLFxuICAgICAgICB0ZW1wbGF0ZVVybDogJ2pzL3Jlc2V0UGFzcy9yZXNldFBhc3MuaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6ICdSZXNldEN0cmwnXG4gICAgfSk7XG59KTtcblxuYXBwLmNvbnRyb2xsZXIoJ1Jlc2V0Q3RybCcsIGZ1bmN0aW9uICgkc2NvcGUsIFVzZXJGYWN0b3J5LCAkc3RhdGVQYXJhbXMsIEF1dGhTZXJ2aWNlLCAkc3RhdGUpIHtcblxuICAgICRzY29wZS5yZXNldFBhc3MgPSBmdW5jdGlvbiAobmV3UGFzcykge1xuICAgICAgICBVc2VyRmFjdG9yeS5lZGl0KCRzdGF0ZVBhcmFtcy51c2VySWQsIHsnbmV3UGFzcyc6IGZhbHNlLCAncGFzc3dvcmQnOiBuZXdQYXNzfSlcbiAgICAgICAgLnRoZW4oIGZ1bmN0aW9uICh1c2VyKSB7XG4gICAgICAgICAgICBBdXRoU2VydmljZS5sb2dpbih7ZW1haWw6IHVzZXIuZW1haWwsIHBhc3N3b3JkOiBuZXdQYXNzfSlcbiAgICAgICAgICAgIC50aGVuKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICAgJHN0YXRlLmdvKCdob21lJyk7XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfSlcbiAgICB9XG59KVxuIiwiYXBwLmNvbmZpZyhmdW5jdGlvbiAoJHN0YXRlUHJvdmlkZXIpIHtcbiAgJHN0YXRlUHJvdmlkZXIuc3RhdGUoJ2xvZ2luJywge1xuICAgIHVybDogJy9sb2dpbicsXG4gICAgdGVtcGxhdGVVcmw6ICdqcy9sb2dpbi9sb2dpbi5odG1sJyxcbiAgICBjb250cm9sbGVyOiAnTG9naW5DdHJsJ1xuICB9KTtcbn0pO1xuXG5hcHAuY29udHJvbGxlcignTG9naW5DdHJsJywgZnVuY3Rpb24gKCRzY29wZSwgQXV0aFNlcnZpY2UsICRzdGF0ZSkge1xuXG4gICRzY29wZS5sb2dpbiA9IHt9O1xuICAkc2NvcGUuZXJyb3IgPSBudWxsO1xuXG4gICRzY29wZS5zZW5kTG9naW4gPSBmdW5jdGlvbiAobG9naW5JbmZvKSB7XG5cbiAgICAkc2NvcGUuZXJyb3IgPSBudWxsO1xuXG4gICAgQXV0aFNlcnZpY2UubG9naW4obG9naW5JbmZvKS50aGVuKGZ1bmN0aW9uICh1c2VyKSB7XG4gICAgICAgIGlmKHVzZXIubmV3UGFzcykgJHN0YXRlLmdvKCdyZXNldFBhc3MnLCB7J3VzZXJJZCc6IHVzZXIuX2lkfSk7XG4gICAgICBlbHNlICRzdGF0ZS5nbygnaG9tZScpO1xuICAgIH0pLmNhdGNoKGZ1bmN0aW9uICgpIHtcbiAgICAgICRzY29wZS5lcnJvciA9ICdJbnZhbGlkIGxvZ2luIGNyZWRlbnRpYWxzLic7XG4gICAgfSk7XG4gIH07XG59KTtcbiIsImFwcC5jb25maWcoZnVuY3Rpb24gKCRzdGF0ZVByb3ZpZGVyKSB7XG5cbiAgICAkc3RhdGVQcm92aWRlci5zdGF0ZSgnc2lnbnVwJywge1xuICAgICAgICB1cmw6ICcvc2lnbnVwJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6ICdqcy9zaWdudXAvc2lnbnVwLmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiAnU2lnbnVwQ3RybCdcbiAgICB9KTtcblxufSk7XG5cbmFwcC5jb250cm9sbGVyKCdTaWdudXBDdHJsJywgZnVuY3Rpb24gKCRzY29wZSwgQXV0aFNlcnZpY2UsICRzdGF0ZSkge1xuXG4gICAgJHNjb3BlLmVycm9yID0gbnVsbDtcblxuICAgICRzY29wZS5zZW5kU2lnbnVwPSBmdW5jdGlvbiAoc2lnbnVwSW5mbykge1xuICAgICAgICAkc2NvcGUuZXJyb3IgPSBudWxsO1xuICAgICAgICBBdXRoU2VydmljZS5zaWdudXAoc2lnbnVwSW5mbylcbiAgICAgICAgLnRoZW4oZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgJHN0YXRlLmdvKCdob21lJyk7XG4gICAgICAgIH0pXG4gICAgICAgIC5jYXRjaChmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAkc2NvcGUuZXJyb3IgPSAnRW1haWwgaXMgdGFrZW4hJztcbiAgICAgICAgfSk7XG5cbiAgICB9O1xuXG59KTtcbiIsImFwcC5jb25maWcoZnVuY3Rpb24oJHN0YXRlUHJvdmlkZXIpe1xuICAkc3RhdGVQcm92aWRlclxuICAuc3RhdGUoJ3VzZXInLCB7XG4gICAgdXJsOiAnL3VzZXIvOnVzZXJJZCcsXG4gICAgdGVtcGxhdGVVcmw6ICcvanMvdXNlci91c2VyLmh0bWwnLFxuICAgIGNvbnRyb2xsZXI6IGZ1bmN0aW9uICgkc2NvcGUsIGZpbmRVc2VyKSB7XG4gICAgICAkc2NvcGUudXNlciA9IGZpbmRVc2VyO1xuICAgIH0sXG4gICAgcmVzb2x2ZToge1xuICAgICAgZmluZFVzZXI6IGZ1bmN0aW9uICgkc3RhdGVQYXJhbXMsIFVzZXJGYWN0b3J5KSB7XG4gICAgICAgIHJldHVybiBVc2VyRmFjdG9yeS5nZXRCeUlkKCRzdGF0ZVBhcmFtcy51c2VySWQpXG4gICAgICAgIC50aGVuKGZ1bmN0aW9uKHVzZXIpe1xuICAgICAgICAgIHJldHVybiB1c2VyO1xuICAgICAgICB9KTtcbiAgICB9XG4gICAgfVxuICB9KTtcbn0pO1xuIiwiYXBwLmNvbmZpZyhmdW5jdGlvbigkc3RhdGVQcm92aWRlcil7XG5cdCRzdGF0ZVByb3ZpZGVyLnN0YXRlKCd1c2VycycsIHtcblx0XHR1cmw6ICcvdXNlcnMnLFxuXHRcdHRlbXBsYXRlVXJsOiAnL2pzL3VzZXJzL3VzZXJzLmh0bWwnLFxuXHRcdHJlc29sdmU6e1xuXHRcdFx0dXNlcnM6IGZ1bmN0aW9uKFVzZXJGYWN0b3J5KXtcblx0XHRcdFx0cmV0dXJuIFVzZXJGYWN0b3J5LmdldEFsbCgpO1xuXHRcdFx0fVxuXHRcdH0sXG5cdFx0Y29udHJvbGxlcjogZnVuY3Rpb24gKCRzY29wZSwgdXNlcnMsIFNlc3Npb24sICRzdGF0ZSkge1xuXHRcdFx0JHNjb3BlLnVzZXJzID0gdXNlcnM7XG5cbiAgICAgICAgICAgIC8vV0hZIE5PVCBPTiBTRVNTSU9OPz8/P1xuXHRcdFx0Ly8gaWYgKCFTZXNzaW9uLnVzZXIgfHwgIVNlc3Npb24udXNlci5pc0FkbWluKXtcblx0XHRcdC8vIFx0JHN0YXRlLmdvKCdob21lJyk7XG5cdFx0XHQvLyB9XG5cdFx0fVxufSk7XG59KTtcbiIsImFwcC5mYWN0b3J5KCdEd2VldEZhY3RvcnknLCBmdW5jdGlvbiAoJGh0dHApIHtcbiAgICB2YXIgRHdlZXRzID0gZnVuY3Rpb24ocHJvcHMpIHtcbiAgICAgICAgYW5ndWxhci5leHRlbmQodGhpcywgcHJvcHMpO1xuICAgIH07XG5cbiAgICBEd2VldHMuZ2V0QWxsID0gZnVuY3Rpb24gKCl7XG4gICAgICAgIHJldHVybiAkaHR0cC5nZXQoJy9hcGkvZGF0YScpXG4gICAgICAgIC50aGVuKGZ1bmN0aW9uIChyZXNwb25zZSl7XG4gICAgICAgICAgICByZXR1cm4gcmVzcG9uc2UuZGF0YTtcbiAgICAgICAgfSlcblx0fTtcblxuICAgIER3ZWV0cy5nZXRMYXRlc3QgPSBmdW5jdGlvbiAoKSB7XG4gICAgICAgIHJldHVybiAkaHR0cC5nZXQoJy9hcGkvZGF0YS9sYXRlc3QnKVxuICAgICAgICAudGhlbiAoZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgICAgICByZXR1cm4gcmVzcG9uc2UuZGF0YTtcbiAgICAgICAgfSlcbiAgICB9O1xuXG4gICAgRHdlZXRzLnBvc3RBbGVydCA9IGZ1bmN0aW9uIChhbGVydCkge1xuICAgICAgICByZXR1cm4gJGh0dHAucG9zdCgnL2FwaS9hbGVydHMnLCBhbGVydClcbiAgICAgICAgLnRoZW4gKCBmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgICAgIHJldHVybiByZXNwb25zZS5kYXRhO1xuICAgICAgICB9KTtcbiAgICB9O1xuXG4gICAgcmV0dXJuIER3ZWV0cztcbn0pXG4iLCJhcHAuZmFjdG9yeSgnVXNlckZhY3RvcnknLCBmdW5jdGlvbigkaHR0cCl7XG5cblx0dmFyIFVzZXIgPSBmdW5jdGlvbihwcm9wcyl7XG5cdFx0YW5ndWxhci5leHRlbmQodGhpcywgcHJvcHMpO1xuXHR9O1xuXG5cdFVzZXIuZ2V0QWxsID0gZnVuY3Rpb24gKCl7XG5cdFx0cmV0dXJuICRodHRwLmdldCgnL2FwaS91c2VycycpXG5cdFx0LnRoZW4oZnVuY3Rpb24ocmVzcG9uc2Upe1xuXHRcdFx0cmV0dXJuIHJlc3BvbnNlLmRhdGE7XG5cdFx0fSk7XG5cdH07XG5cblx0VXNlci5nZXRCeUlkID0gZnVuY3Rpb24gKGlkKSB7XG5cdFx0cmV0dXJuICRodHRwLmdldCgnL2FwaS91c2Vycy8nICsgaWQpXG5cdFx0LnRoZW4oZnVuY3Rpb24ocmVzcG9uc2Upe1xuXHRcdFx0cmV0dXJuIHJlc3BvbnNlLmRhdGE7XG5cdFx0fSk7XG5cdH07XG5cblx0VXNlci5lZGl0ID0gZnVuY3Rpb24gKGlkLCBwcm9wcykge1xuXHRcdHJldHVybiAkaHR0cC5wdXQoJy9hcGkvdXNlcnMvJyArIGlkLCBwcm9wcylcblx0XHQudGhlbihmdW5jdGlvbihyZXNwb25zZSl7XG5cdFx0XHRyZXR1cm4gcmVzcG9uc2UuZGF0YTtcblx0XHR9KTtcblx0fTtcblxuXHRVc2VyLmRlbGV0ZSA9IGZ1bmN0aW9uIChpZCkge1xuXHRcdHJldHVybiAkaHR0cC5kZWxldGUoJy9hcGkvdXNlcnMvJyArIGlkKVxuXHRcdC50aGVuKGZ1bmN0aW9uKHJlc3BvbnNlKXtcblx0XHRcdFx0cmV0dXJuIHJlc3BvbnNlLmRhdGE7XG5cdFx0fSk7XG5cdH07XG5cblxuXHRyZXR1cm4gVXNlcjtcbn0pO1xuIiwiYXBwLmRpcmVjdGl2ZShcImVkaXRCdXR0b25cIiwgZnVuY3Rpb24gKCkge1xuXHRyZXR1cm4ge1xuXHRcdHJlc3RyaWN0OiAnRUEnLFxuXHRcdHRlbXBsYXRlVXJsOiAnanMvY29tbW9uL2RpcmVjdGl2ZXMvZWRpdC1idXR0b24vZWRpdC1idXR0b24uaHRtbCcsXG5cdH07XG59KTtcbiIsImFwcC5kaXJlY3RpdmUoJ2R3ZWV0TGlzdCcsIGZ1bmN0aW9uKCl7XG4gIHJldHVybiB7XG4gICAgcmVzdHJpY3Q6ICdFJyxcbiAgICB0ZW1wbGF0ZVVybDogJy9qcy9jb21tb24vZGlyZWN0aXZlcy9kd2VldC9kd2VldC1saXN0Lmh0bWwnXG4gIH07XG59KTtcbiIsImFwcC5kaXJlY3RpdmUoJ25hdmJhcicsIGZ1bmN0aW9uICgkcm9vdFNjb3BlLCBBdXRoU2VydmljZSwgQVVUSF9FVkVOVFMsICRzdGF0ZSkge1xuXG4gICAgcmV0dXJuIHtcbiAgICAgICAgcmVzdHJpY3Q6ICdFJyxcbiAgICAgICAgc2NvcGU6IHt9LFxuICAgICAgICB0ZW1wbGF0ZVVybDogJ2pzL2NvbW1vbi9kaXJlY3RpdmVzL25hdmJhci9uYXZiYXIuaHRtbCcsXG4gICAgICAgIGxpbms6IGZ1bmN0aW9uIChzY29wZSkge1xuXG4gICAgICAgICAgICBzY29wZS5pdGVtcyA9IFtcbiAgICAgICAgICAgICAgICB7IGxhYmVsOiAnQWxlcnRzJywgc3RhdGU6ICdhbGVydHMnIH0sXG4gICAgICAgICAgICAgICAgeyBsYWJlbDogJ0RhdGEnLCBzdGF0ZTogJ2RhdGEnIH0sXG4gICAgICAgICAgICAgICAgeyBsYWJlbDogJ0xhdGVzdCcsIHN0YXRlOiAnbGF0ZXN0JyB9LFxuICAgICAgICAgICAgICAgIHsgbGFiZWw6ICdVc2VycycsIHN0YXRlOiAndXNlcnMnIH0sXG4gICAgICAgICAgICAgICAgeyBsYWJlbDogJ0RvY3VtZW50YXRpb24nLCBzdGF0ZTogJ2RvY3MnIH1cbiAgICAgICAgICAgIF07XG5cbiAgICAgICAgICAgIHNjb3BlLnVzZXIgPSBudWxsO1xuXG4gICAgICAgICAgICBzY29wZS5pc0xvZ2dlZEluID0gZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgIHJldHVybiBBdXRoU2VydmljZS5pc0F1dGhlbnRpY2F0ZWQoKTtcbiAgICAgICAgICAgIH07XG5cbiAgICAgICAgICAgIHNjb3BlLmxvZ291dCA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICAgICBBdXRoU2VydmljZS5sb2dvdXQoKS50aGVuKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICAgICAgICRzdGF0ZS5nbygnaG9tZScpO1xuICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgfTtcblxuICAgICAgICAgICAgdmFyIHNldFVzZXIgPSBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAgICAgQXV0aFNlcnZpY2UuZ2V0TG9nZ2VkSW5Vc2VyKCkudGhlbihmdW5jdGlvbiAodXNlcikge1xuICAgICAgICAgICAgICAgICAgICBzY29wZS51c2VyID0gdXNlcjtcbiAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgIH07XG5cbiAgICAgICAgICAgIHZhciByZW1vdmVVc2VyID0gZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgIHNjb3BlLnVzZXIgPSBudWxsO1xuICAgICAgICAgICAgfTtcblxuICAgICAgICAgICAgc2V0VXNlcigpO1xuXG4gICAgICAgICAgICAkcm9vdFNjb3BlLiRvbihBVVRIX0VWRU5UUy5sb2dpblN1Y2Nlc3MsIHNldFVzZXIpO1xuICAgICAgICAgICAgJHJvb3RTY29wZS4kb24oQVVUSF9FVkVOVFMuc2lnbnVwU3VjY2Vzcywgc2V0VXNlcik7XG4gICAgICAgICAgICAkcm9vdFNjb3BlLiRvbihBVVRIX0VWRU5UUy5sb2dvdXRTdWNjZXNzLCByZW1vdmVVc2VyKTtcbiAgICAgICAgICAgICRyb290U2NvcGUuJG9uKEFVVEhfRVZFTlRTLnNlc3Npb25UaW1lb3V0LCByZW1vdmVVc2VyKTtcblxuICAgICAgICB9XG5cbiAgICB9O1xuXG59KTtcbiIsImFwcC5kaXJlY3RpdmUoXCJlZGl0UGFzc0J1dHRvblwiLCBmdW5jdGlvbiAoKSB7XG5cdHJldHVybiB7XG5cdFx0cmVzdHJpY3Q6ICdFQScsXG5cdFx0dGVtcGxhdGVVcmw6ICdqcy9jb21tb24vZGlyZWN0aXZlcy9lZGl0LXBhc3MtYnV0dG9uL2VkaXQtcGFzcy1idXR0b24uaHRtbCcsXG5cdH07XG59KTtcbiIsImFwcC5kaXJlY3RpdmUoJ3VzZXJEZXRhaWwnLCBmdW5jdGlvbihVc2VyRmFjdG9yeSwgJHN0YXRlUGFyYW1zLCAkc3RhdGUsIFNlc3Npb24pe1xuICByZXR1cm4ge1xuXHRyZXN0cmljdDogJ0UnLFxuXHR0ZW1wbGF0ZVVybDogJy9qcy9jb21tb24vZGlyZWN0aXZlcy91c2VyL3VzZXItZGV0YWlsL3VzZXItZGV0YWlsLmh0bWwnLFxuXHRsaW5rOiBmdW5jdGlvbiAoc2NvcGUpe1xuXHRcdHNjb3BlLmlzRGV0YWlsID0gdHJ1ZTtcblx0XHRzY29wZS5pc0FkbWluID0gU2Vzc2lvbi51c2VyLmlzQWRtaW47XG5cdFx0c2NvcGUuZWRpdE1vZGUgPSBmYWxzZTtcbiAgICAgICAgc2NvcGUuZWRpdFBhc3MgPSBmYWxzZTtcblxuICAgICAgICAvL0ZJWCBUSElTIExJTkVcbiAgICAgICAgaWYgKHNjb3BlLnVzZXIgPSBTZXNzaW9uLnVzZXIpIHNjb3BlLmlzT3duZXIgPSB0cnVlXG5cblx0XHRzY29wZS5lbmFibGVFZGl0ID0gZnVuY3Rpb24gKCkge1xuXHRcdFx0c2NvcGUuY2FjaGVkID0gYW5ndWxhci5jb3B5KHNjb3BlLnVzZXIpO1xuXHRcdFx0c2NvcGUuZWRpdE1vZGUgPSB0cnVlO1xuXHRcdH07XG5cdFx0c2NvcGUuY2FuY2VsRWRpdCA9IGZ1bmN0aW9uKCl7XG5cdFx0XHRzY29wZS51c2VyID0gYW5ndWxhci5jb3B5KHNjb3BlLmNhY2hlZCk7XG5cdFx0XHRzY29wZS5lZGl0TW9kZSA9IGZhbHNlO1xuICAgICAgICAgICAgc2NvcGUuZWRpdFBhc3M9IGZhbHNlO1xuXHRcdH07XG5cdFx0c2NvcGUuc2F2ZVVzZXIgPSBmdW5jdGlvbiAodXNlcikge1xuXHRcdFx0VXNlckZhY3RvcnkuZWRpdCh1c2VyLl9pZCwgdXNlcilcblx0XHRcdC50aGVuKGZ1bmN0aW9uICh1cGRhdGVkVXNlcikge1xuXHRcdFx0XHRzY29wZS51c2VyID0gdXBkYXRlZFVzZXI7XG5cdFx0XHRcdHNjb3BlLmVkaXRNb2RlID0gZmFsc2U7XG4gICAgICAgICAgICAgICAgc2NvcGUuZWRpdFBhc3M9IGZhbHNlO1xuXHRcdFx0fSk7XG5cdFx0fTtcblx0XHRzY29wZS5kZWxldGVVc2VyID0gZnVuY3Rpb24odXNlcil7XG5cdFx0XHRVc2VyRmFjdG9yeS5kZWxldGUodXNlcilcblx0XHRcdC50aGVuKGZ1bmN0aW9uKCl7XG5cdFx0XHRcdHNjb3BlLmVkaXRNb2RlID0gZmFsc2U7XG4gICAgICAgICAgICAgICAgc2NvcGUuZWRpdFBhc3M9IGZhbHNlO1xuXHRcdFx0XHQkc3RhdGUuZ28oJ2hvbWUnKTtcblx0XHRcdH0pO1xuXHRcdH07XG5cbiAgICAgICAgc2NvcGUucGFzc3dvcmRFZGl0ID0gZnVuY3Rpb24oKXtcbiAgICAgICAgICAgIC8vIFVzZXJGYWN0b3J5LmVkaXQoaWQsIHsnbmV3UGFzcyc6IHRydWV9KVxuICAgICAgICAgICAgLy8gLnRoZW4oZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgLy8gICAgIC8vIHNjb3BlLm5ld1Bhc3MgPSB0cnVlO1xuICAgICAgICAgICAgLy8gICAgIHNjb3BlLmVkaXRNb2RlID0gZmFsc2U7XG4gICAgICAgICAgICAvLyB9KTtcbiAgICAgICAgICAgIHNjb3BlLmNhY2hlZCA9IGFuZ3VsYXIuY29weShzY29wZS51c2VyKTtcbiAgICAgICAgICAgIHNjb3BlLmVkaXRQYXNzID0gdHJ1ZTtcbiAgICAgICAgfTtcblx0fSxcblx0c2NvcGU6IHtcblx0XHR1c2VyOiBcIj1cIlxuXHR9XG4gIH07XG59KTtcbiIsImFwcC5kaXJlY3RpdmUoJ3VzZXJMaXN0JywgZnVuY3Rpb24oKXtcbiAgcmV0dXJuIHtcbiAgICByZXN0cmljdDogJ0UnLFxuICAgIHRlbXBsYXRlVXJsOiAnL2pzL2NvbW1vbi9kaXJlY3RpdmVzL3VzZXIvdXNlci1saXN0L3VzZXItbGlzdC5odG1sJ1xuICB9O1xufSk7XG4iXSwic291cmNlUm9vdCI6Ii9zb3VyY2UvIn0=