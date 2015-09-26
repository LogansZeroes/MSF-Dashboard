'use strict';
window.app = angular.module('FullstackGeneratedApp', ['ui.router', 'ui.bootstrap', 'fsaPreBuilt']);

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
        controller: function controller($scope, DweetFactory) {
            //Create array of latest dweets to display on home state
            $scope.homeDweets = [];

            //Initialize with first dweet
            DweetFactory.getLatest().then(function (dweet) {
                $scope.prevDweet = dweet;
            });

            var line1 = new TimeSeries();
            var line2 = new TimeSeries();

            //Check every half second to see if the last dweet is new, then push to homeDweets, then plot
            setInterval(function () {
                DweetFactory.getLatest().then(function (dweet) {
                    $scope.lastDweet = dweet;
                }).then(function () {
                    if ($scope.prevDweet.created != $scope.lastDweet.created) {
                        $scope.homeDweets.push($scope.lastDweet);
                        $scope.prevDweet = $scope.lastDweet;
                        line1.append(new Date().getTime(), $scope.lastDweet.content['Temperature']);
                        //Random plot to check that the graph is working
                        line2.append(new Date().getTime(), Math.floor(Math.random() * 3 + 72));
                    }
                });
            }, 100);

            //Make a smoothie chart with aesthetically pleasing properties
            var smoothie = new SmoothieChart({
                grid: {
                    strokeStyle: 'rgb(63, 160, 182)',
                    fillStyle: 'rgb(4, 5, 91)',
                    lineWidth: 1,
                    millisPerLine: 500,
                    verticalSections: 4
                },
                // maxValue: 73,
                // minValue: 72,
                maxValueScale: 1.005,
                minValueScale: 1.005,
                timestampFormatter: SmoothieChart.timeFormatter,
                //The range of acceptable temperatures should be below
                horizontalLines: [{
                    color: '#880000',
                    lineWidth: 2,
                    value: 73
                }, {
                    color: '#880000',
                    lineWidth: 2,
                    value: 72
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
            // findDweets: function (DweetFactory) {
            //     return DweetFactory.getAll();
            // };
            latestDweet: function latestDweet(DweetFactory) {
                return DweetFactory.getLatest();
            }
        }
    });
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

            scope.items = [{ label: 'Users', state: 'users' }, { label: 'Data', state: 'data' }, { label: 'Latest', state: 'latest' }, { label: 'Documentation', state: 'docs' }];

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

app.directive("editButton", function () {
    return {
        restrict: 'EA',
        templateUrl: 'js/common/directives/edit-button/edit-button.html'
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

            scope.enableEdit = function () {
                scope.cached = angular.copy(scope.user);
                scope.editMode = true;
            };
            scope.cancelEdit = function () {
                scope.user = angular.copy(scope.cached);
                scope.editMode = false;
            };
            scope.saveUser = function (user) {
                UserFactory.edit(user._id, user).then(function (updatedUser) {
                    scope.user = updatedUser;
                    scope.editMode = false;
                });
            };
            scope.deleteUser = function (user) {
                UserFactory['delete'](user).then(function () {
                    scope.editMode = false;
                    $state.go('home');
                });
            };

            scope.resetPass = function (id) {
                UserFactory.edit(id, { 'newPass': true }).then(function () {
                    // scope.newPass = true;
                    scope.editMode = false;
                });
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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbImFwcC5qcyIsImRhdGEvZGF0YS5qcyIsImRvY3MvZG9jcy5qcyIsImZzYS9mc2EtcHJlLWJ1aWx0LmpzIiwiaG9tZS9ob21lLmpzIiwibGF0ZXN0L2xhdGVzdC5qcyIsImxvZ2luL2xvZ2luLmpzIiwicmVzZXRQYXNzL3Jlc2V0UGFzcy5qcyIsInNpZ251cC9zaWdudXAuanMiLCJ1c2VyL3VzZXIuanMiLCJ1c2Vycy91c2Vycy5qcyIsImNvbW1vbi9mYWN0b3JpZXMvZHdlZXQtZmFjdG9yeS5qcyIsImNvbW1vbi9mYWN0b3JpZXMvdXNlci1mYWN0b3J5LmpzIiwiY29tbW9uL2RpcmVjdGl2ZXMvZHdlZXQvZHdlZXQtbGlzdC5qcyIsImNvbW1vbi9kaXJlY3RpdmVzL25hdmJhci9uYXZiYXIuanMiLCJjb21tb24vZGlyZWN0aXZlcy9lZGl0LWJ1dHRvbi9lZGl0LWJ1dHRvbi5qcyIsImNvbW1vbi9kaXJlY3RpdmVzL3VzZXIvdXNlci1kZXRhaWwvdXNlci1kZXRhaWwuanMiLCJjb21tb24vZGlyZWN0aXZlcy91c2VyL3VzZXItbGlzdC91c2VyLWxpc3QuanMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6IkFBQUEsWUFBQSxDQUFBO0FBQ0EsTUFBQSxDQUFBLEdBQUEsR0FBQSxPQUFBLENBQUEsTUFBQSxDQUFBLHVCQUFBLEVBQUEsQ0FBQSxXQUFBLEVBQUEsY0FBQSxFQUFBLGFBQUEsQ0FBQSxDQUFBLENBQUE7O0FBRUEsR0FBQSxDQUFBLE1BQUEsQ0FBQSxVQUFBLGtCQUFBLEVBQUEsaUJBQUEsRUFBQTs7O0FBR0Esc0JBQUEsQ0FBQSxJQUFBLENBQUEsVUFBQSxTQUFBLEVBQUEsU0FBQSxFQUFBOztBQUVBLFlBQUEsRUFBQSxHQUFBLG1CQUFBLENBQUE7QUFDQSxZQUFBLElBQUEsR0FBQSxTQUFBLENBQUEsR0FBQSxFQUFBLENBQUE7O0FBRUEsWUFBQSxFQUFBLENBQUEsSUFBQSxDQUFBLElBQUEsQ0FBQSxFQUFBO0FBQ0EsbUJBQUEsSUFBQSxDQUFBLE9BQUEsQ0FBQSxFQUFBLEVBQUEsTUFBQSxDQUFBLENBQUE7U0FDQTs7QUFFQSxlQUFBLEtBQUEsQ0FBQTtLQUNBLENBQUEsQ0FBQTs7QUFFQSxxQkFBQSxDQUFBLFNBQUEsQ0FBQSxJQUFBLENBQUEsQ0FBQTtBQUNBLHNCQUFBLENBQUEsSUFBQSxDQUFBLGlCQUFBLEVBQUEsWUFBQTtBQUNBLGNBQUEsQ0FBQSxRQUFBLENBQUEsTUFBQSxFQUFBLENBQUE7S0FDQSxDQUFBLENBQUE7O0FBRUEsc0JBQUEsQ0FBQSxTQUFBLENBQUEsR0FBQSxDQUFBLENBQUE7Q0FFQSxDQUFBLENBQUE7OztBQUdBLEdBQUEsQ0FBQSxHQUFBLENBQUEsVUFBQSxVQUFBLEVBQUEsV0FBQSxFQUFBLE1BQUEsRUFBQTs7O0FBR0EsUUFBQSw0QkFBQSxHQUFBLFNBQUEsNEJBQUEsQ0FBQSxLQUFBLEVBQUE7QUFDQSxlQUFBLEtBQUEsQ0FBQSxJQUFBLElBQUEsS0FBQSxDQUFBLElBQUEsQ0FBQSxZQUFBLENBQUE7S0FDQSxDQUFBOzs7O0FBSUEsY0FBQSxDQUFBLEdBQUEsQ0FBQSxtQkFBQSxFQUFBLFVBQUEsS0FBQSxFQUFBLE9BQUEsRUFBQSxRQUFBLEVBQUE7O0FBRUEsWUFBQSxDQUFBLDRCQUFBLENBQUEsT0FBQSxDQUFBLEVBQUE7OztBQUdBLG1CQUFBO1NBQ0E7O0FBRUEsWUFBQSxXQUFBLENBQUEsZUFBQSxFQUFBLEVBQUE7OztBQUdBLG1CQUFBO1NBQ0E7OztBQUdBLGFBQUEsQ0FBQSxjQUFBLEVBQUEsQ0FBQTs7QUFFQSxtQkFBQSxDQUFBLGVBQUEsRUFBQSxDQUFBLElBQUEsQ0FBQSxVQUFBLElBQUEsRUFBQTs7OztBQUlBLGdCQUFBLElBQUEsRUFBQTtBQUNBLHNCQUFBLENBQUEsRUFBQSxDQUFBLE9BQUEsQ0FBQSxJQUFBLEVBQUEsUUFBQSxDQUFBLENBQUE7YUFDQSxNQUFBO0FBQ0Esc0JBQUEsQ0FBQSxFQUFBLENBQUEsT0FBQSxDQUFBLENBQUE7YUFDQTtTQUNBLENBQUEsQ0FBQTtLQUVBLENBQUEsQ0FBQTtDQUVBLENBQUEsQ0FBQTs7QUNuRUEsR0FBQSxDQUFBLE1BQUEsQ0FBQSxVQUFBLGNBQUEsRUFBQTtBQUNBLGtCQUFBLENBQ0EsS0FBQSxDQUFBLE1BQUEsRUFBQTtBQUNBLFdBQUEsRUFBQSxPQUFBO0FBQ0EsbUJBQUEsRUFBQSxtQkFBQTtBQUNBLGtCQUFBLEVBQUEsb0JBQUEsTUFBQSxFQUFBLFNBQUEsRUFBQTtBQUNBLGtCQUFBLENBQUEsTUFBQSxHQUFBLFNBQUEsQ0FBQTtTQUNBO0FBQ0EsZUFBQSxFQUFBOzs7O0FBSUEscUJBQUEsRUFBQSxtQkFBQSxZQUFBLEVBQUE7QUFDQSx1QkFBQSxZQUFBLENBQUEsTUFBQSxFQUFBLENBQUE7YUFDQTtTQUNBO0tBQ0EsQ0FBQSxDQUFBO0NBQ0EsQ0FBQSxDQUFBOztBQ2pCQSxHQUFBLENBQUEsTUFBQSxDQUFBLFVBQUEsY0FBQSxFQUFBO0FBQ0Esa0JBQUEsQ0FBQSxLQUFBLENBQUEsTUFBQSxFQUFBO0FBQ0EsV0FBQSxFQUFBLE9BQUE7QUFDQSxtQkFBQSxFQUFBLG1CQUFBO0tBQ0EsQ0FBQSxDQUFBO0NBQ0EsQ0FBQSxDQUFBOztBQ0xBLENBQUEsWUFBQTs7QUFFQSxnQkFBQSxDQUFBOzs7QUFHQSxRQUFBLENBQUEsTUFBQSxDQUFBLE9BQUEsRUFBQSxNQUFBLElBQUEsS0FBQSxDQUFBLHdCQUFBLENBQUEsQ0FBQTs7QUFFQSxRQUFBLEdBQUEsR0FBQSxPQUFBLENBQUEsTUFBQSxDQUFBLGFBQUEsRUFBQSxFQUFBLENBQUEsQ0FBQTs7QUFFQSxPQUFBLENBQUEsT0FBQSxDQUFBLFFBQUEsRUFBQSxZQUFBO0FBQ0EsWUFBQSxDQUFBLE1BQUEsQ0FBQSxFQUFBLEVBQUEsTUFBQSxJQUFBLEtBQUEsQ0FBQSxzQkFBQSxDQUFBLENBQUE7QUFDQSxlQUFBLE1BQUEsQ0FBQSxFQUFBLENBQUEsTUFBQSxDQUFBLFFBQUEsQ0FBQSxNQUFBLENBQUEsQ0FBQTtLQUNBLENBQUEsQ0FBQTs7Ozs7QUFLQSxPQUFBLENBQUEsUUFBQSxDQUFBLGFBQUEsRUFBQTtBQUNBLG9CQUFBLEVBQUEsb0JBQUE7QUFDQSxtQkFBQSxFQUFBLG1CQUFBO0FBQ0EscUJBQUEsRUFBQSxxQkFBQTtBQUNBLG9CQUFBLEVBQUEsb0JBQUE7QUFDQSxxQkFBQSxFQUFBLHFCQUFBO0FBQ0Esc0JBQUEsRUFBQSxzQkFBQTtBQUNBLHdCQUFBLEVBQUEsd0JBQUE7QUFDQSxxQkFBQSxFQUFBLHFCQUFBO0tBQ0EsQ0FBQSxDQUFBOztBQUVBLE9BQUEsQ0FBQSxPQUFBLENBQUEsaUJBQUEsRUFBQSxVQUFBLFVBQUEsRUFBQSxFQUFBLEVBQUEsV0FBQSxFQUFBO0FBQ0EsWUFBQSxVQUFBLEdBQUE7QUFDQSxlQUFBLEVBQUEsV0FBQSxDQUFBLGdCQUFBO0FBQ0EsZUFBQSxFQUFBLFdBQUEsQ0FBQSxhQUFBO0FBQ0EsZUFBQSxFQUFBLFdBQUEsQ0FBQSxjQUFBO0FBQ0EsZUFBQSxFQUFBLFdBQUEsQ0FBQSxjQUFBO1NBQ0EsQ0FBQTtBQUNBLGVBQUE7QUFDQSx5QkFBQSxFQUFBLHVCQUFBLFFBQUEsRUFBQTtBQUNBLDBCQUFBLENBQUEsVUFBQSxDQUFBLFVBQUEsQ0FBQSxRQUFBLENBQUEsTUFBQSxDQUFBLEVBQUEsUUFBQSxDQUFBLENBQUE7QUFDQSx1QkFBQSxFQUFBLENBQUEsTUFBQSxDQUFBLFFBQUEsQ0FBQSxDQUFBO2FBQ0E7U0FDQSxDQUFBO0tBQ0EsQ0FBQSxDQUFBOztBQUVBLE9BQUEsQ0FBQSxNQUFBLENBQUEsVUFBQSxhQUFBLEVBQUE7QUFDQSxxQkFBQSxDQUFBLFlBQUEsQ0FBQSxJQUFBLENBQUEsQ0FDQSxXQUFBLEVBQ0EsVUFBQSxTQUFBLEVBQUE7QUFDQSxtQkFBQSxTQUFBLENBQUEsR0FBQSxDQUFBLGlCQUFBLENBQUEsQ0FBQTtTQUNBLENBQ0EsQ0FBQSxDQUFBO0tBQ0EsQ0FBQSxDQUFBOztBQUVBLE9BQUEsQ0FBQSxPQUFBLENBQUEsYUFBQSxFQUFBLFVBQUEsS0FBQSxFQUFBLE9BQUEsRUFBQSxVQUFBLEVBQUEsV0FBQSxFQUFBLEVBQUEsRUFBQTs7QUFFQSxpQkFBQSxpQkFBQSxDQUFBLFFBQUEsRUFBQTtBQUNBLGdCQUFBLElBQUEsR0FBQSxRQUFBLENBQUEsSUFBQSxDQUFBO0FBQ0EsbUJBQUEsQ0FBQSxNQUFBLENBQUEsSUFBQSxDQUFBLEVBQUEsRUFBQSxJQUFBLENBQUEsSUFBQSxDQUFBLENBQUE7QUFDQSxzQkFBQSxDQUFBLFVBQUEsQ0FBQSxXQUFBLENBQUEsWUFBQSxDQUFBLENBQUE7QUFDQSxtQkFBQSxJQUFBLENBQUEsSUFBQSxDQUFBO1NBQ0E7OztBQUdBLGlCQUFBLGtCQUFBLENBQUEsUUFBQSxFQUFBO0FBQ0EsZ0JBQUEsSUFBQSxHQUFBLFFBQUEsQ0FBQSxJQUFBLENBQUE7QUFDQSxtQkFBQSxDQUFBLE1BQUEsQ0FBQSxJQUFBLENBQUEsRUFBQSxFQUFBLElBQUEsQ0FBQSxJQUFBLENBQUEsQ0FBQTtBQUNBLHNCQUFBLENBQUEsVUFBQSxDQUFBLFdBQUEsQ0FBQSxhQUFBLENBQUEsQ0FBQTtBQUNBLG1CQUFBLElBQUEsQ0FBQSxJQUFBLENBQUE7U0FDQTs7OztBQUlBLFlBQUEsQ0FBQSxlQUFBLEdBQUEsWUFBQTtBQUNBLG1CQUFBLENBQUEsQ0FBQSxPQUFBLENBQUEsSUFBQSxDQUFBO1NBQ0EsQ0FBQTs7QUFFQSxZQUFBLENBQUEsZUFBQSxHQUFBLFVBQUEsVUFBQSxFQUFBOzs7Ozs7Ozs7O0FBVUEsZ0JBQUEsSUFBQSxDQUFBLGVBQUEsRUFBQSxJQUFBLFVBQUEsS0FBQSxJQUFBLEVBQUE7QUFDQSx1QkFBQSxFQUFBLENBQUEsSUFBQSxDQUFBLE9BQUEsQ0FBQSxJQUFBLENBQUEsQ0FBQTthQUNBOzs7OztBQUtBLG1CQUFBLEtBQUEsQ0FBQSxHQUFBLENBQUEsVUFBQSxDQUFBLENBQUEsSUFBQSxDQUFBLGlCQUFBLENBQUEsU0FBQSxDQUFBLFlBQUE7QUFDQSx1QkFBQSxJQUFBLENBQUE7YUFDQSxDQUFBLENBQUE7U0FFQSxDQUFBOztBQUVBLFlBQUEsQ0FBQSxLQUFBLEdBQUEsVUFBQSxXQUFBLEVBQUE7QUFDQSxtQkFBQSxLQUFBLENBQUEsSUFBQSxDQUFBLFFBQUEsRUFBQSxXQUFBLENBQUEsQ0FDQSxJQUFBLENBQUEsaUJBQUEsQ0FBQSxTQUNBLENBQUEsWUFBQTtBQUNBLHVCQUFBLEVBQUEsQ0FBQSxNQUFBLENBQUEsRUFBQSxPQUFBLEVBQUEsNEJBQUEsRUFBQSxDQUFBLENBQUE7YUFDQSxDQUFBLENBQUE7U0FDQSxDQUFBOztBQUVBLFlBQUEsQ0FBQSxNQUFBLEdBQUEsWUFBQTtBQUNBLG1CQUFBLEtBQUEsQ0FBQSxHQUFBLENBQUEsU0FBQSxDQUFBLENBQUEsSUFBQSxDQUFBLFlBQUE7QUFDQSx1QkFBQSxDQUFBLE9BQUEsRUFBQSxDQUFBO0FBQ0EsMEJBQUEsQ0FBQSxVQUFBLENBQUEsV0FBQSxDQUFBLGFBQUEsQ0FBQSxDQUFBO2FBQ0EsQ0FBQSxDQUFBO1NBQ0EsQ0FBQTs7QUFFQSxZQUFBLENBQUEsTUFBQSxHQUFBLFVBQUEsV0FBQSxFQUFBO0FBQ0EsbUJBQUEsS0FBQSxDQUFBLElBQUEsQ0FBQSxTQUFBLEVBQUEsV0FBQSxDQUFBLENBQ0EsSUFBQSxDQUFBLGtCQUFBLENBQUEsQ0FBQTtTQUNBLENBQUE7S0FHQSxDQUFBLENBQUE7O0FBRUEsT0FBQSxDQUFBLE9BQUEsQ0FBQSxTQUFBLEVBQUEsVUFBQSxVQUFBLEVBQUEsV0FBQSxFQUFBOztBQUVBLFlBQUEsSUFBQSxHQUFBLElBQUEsQ0FBQTs7QUFFQSxrQkFBQSxDQUFBLEdBQUEsQ0FBQSxXQUFBLENBQUEsZ0JBQUEsRUFBQSxZQUFBO0FBQ0EsZ0JBQUEsQ0FBQSxPQUFBLEVBQUEsQ0FBQTtTQUNBLENBQUEsQ0FBQTs7QUFFQSxrQkFBQSxDQUFBLEdBQUEsQ0FBQSxXQUFBLENBQUEsY0FBQSxFQUFBLFlBQUE7QUFDQSxnQkFBQSxDQUFBLE9BQUEsRUFBQSxDQUFBO1NBQ0EsQ0FBQSxDQUFBOztBQUVBLFlBQUEsQ0FBQSxFQUFBLEdBQUEsSUFBQSxDQUFBO0FBQ0EsWUFBQSxDQUFBLElBQUEsR0FBQSxJQUFBLENBQUE7O0FBRUEsWUFBQSxDQUFBLE1BQUEsR0FBQSxVQUFBLFNBQUEsRUFBQSxJQUFBLEVBQUE7QUFDQSxnQkFBQSxDQUFBLEVBQUEsR0FBQSxTQUFBLENBQUE7QUFDQSxnQkFBQSxDQUFBLElBQUEsR0FBQSxJQUFBLENBQUE7U0FDQSxDQUFBOztBQUVBLFlBQUEsQ0FBQSxPQUFBLEdBQUEsWUFBQTtBQUNBLGdCQUFBLENBQUEsRUFBQSxHQUFBLElBQUEsQ0FBQTtBQUNBLGdCQUFBLENBQUEsSUFBQSxHQUFBLElBQUEsQ0FBQTtTQUNBLENBQUE7S0FFQSxDQUFBLENBQUE7Q0FFQSxDQUFBLEVBQUEsQ0FBQTs7QUNwSkEsR0FBQSxDQUFBLE1BQUEsQ0FBQSxVQUFBLGNBQUEsRUFBQTtBQUNBLGtCQUFBLENBQUEsS0FBQSxDQUFBLE1BQUEsRUFBQTtBQUNBLFdBQUEsRUFBQSxHQUFBO0FBQ0EsbUJBQUEsRUFBQSxtQkFBQTtBQUNBLGtCQUFBLEVBQUEsb0JBQUEsTUFBQSxFQUFBLFlBQUEsRUFBQTs7QUFFQSxrQkFBQSxDQUFBLFVBQUEsR0FBQSxFQUFBLENBQUE7OztBQUdBLHdCQUFBLENBQUEsU0FBQSxFQUFBLENBQ0EsSUFBQSxDQUFBLFVBQUEsS0FBQSxFQUFBO0FBQ0Esc0JBQUEsQ0FBQSxTQUFBLEdBQUEsS0FBQSxDQUFBO2FBQ0EsQ0FBQSxDQUFBOztBQUVBLGdCQUFBLEtBQUEsR0FBQSxJQUFBLFVBQUEsRUFBQSxDQUFBO0FBQ0EsZ0JBQUEsS0FBQSxHQUFBLElBQUEsVUFBQSxFQUFBLENBQUE7OztBQUdBLHVCQUFBLENBQUEsWUFBQTtBQUNBLDRCQUFBLENBQUEsU0FBQSxFQUFBLENBQ0EsSUFBQSxDQUFBLFVBQUEsS0FBQSxFQUFBO0FBQ0EsMEJBQUEsQ0FBQSxTQUFBLEdBQUEsS0FBQSxDQUFBO2lCQUNBLENBQUEsQ0FDQSxJQUFBLENBQUEsWUFBQTtBQUNBLHdCQUFBLE1BQUEsQ0FBQSxTQUFBLENBQUEsT0FBQSxJQUFBLE1BQUEsQ0FBQSxTQUFBLENBQUEsT0FBQSxFQUNBO0FBQ0EsOEJBQUEsQ0FBQSxVQUFBLENBQUEsSUFBQSxDQUFBLE1BQUEsQ0FBQSxTQUFBLENBQUEsQ0FBQTtBQUNBLDhCQUFBLENBQUEsU0FBQSxHQUFBLE1BQUEsQ0FBQSxTQUFBLENBQUE7QUFDQSw2QkFBQSxDQUFBLE1BQUEsQ0FBQSxJQUFBLElBQUEsRUFBQSxDQUFBLE9BQUEsRUFBQSxFQUFBLE1BQUEsQ0FBQSxTQUFBLENBQUEsT0FBQSxDQUFBLGFBQUEsQ0FBQSxDQUFBLENBQUE7O0FBRUEsNkJBQUEsQ0FBQSxNQUFBLENBQUEsSUFBQSxJQUFBLEVBQUEsQ0FBQSxPQUFBLEVBQUEsRUFBQSxJQUFBLENBQUEsS0FBQSxDQUFBLElBQUEsQ0FBQSxNQUFBLEVBQUEsR0FBQSxDQUFBLEdBQUEsRUFBQSxDQUFBLENBQUEsQ0FBQTtxQkFDQTtpQkFDQSxDQUFBLENBQUE7YUFFQSxFQUFBLEdBQUEsQ0FBQSxDQUFBOzs7QUFHQSxnQkFBQSxRQUFBLEdBQUEsSUFBQSxhQUFBLENBQUE7QUFDQSxvQkFBQSxFQUFBO0FBQ0EsK0JBQUEsRUFBQSxtQkFBQTtBQUNBLDZCQUFBLEVBQUEsZUFBQTtBQUNBLDZCQUFBLEVBQUEsQ0FBQTtBQUNBLGlDQUFBLEVBQUEsR0FBQTtBQUNBLG9DQUFBLEVBQUEsQ0FBQTtpQkFDQTs7O0FBR0EsNkJBQUEsRUFBQSxLQUFBO0FBQ0EsNkJBQUEsRUFBQSxLQUFBO0FBQ0Esa0NBQUEsRUFBQSxhQUFBLENBQUEsYUFBQTs7QUFFQSwrQkFBQSxFQUFBLENBQUE7QUFDQSx5QkFBQSxFQUFBLFNBQUE7QUFDQSw2QkFBQSxFQUFBLENBQUE7QUFDQSx5QkFBQSxFQUFBLEVBQUE7aUJBQ0EsRUFBQTtBQUNBLHlCQUFBLEVBQUEsU0FBQTtBQUNBLDZCQUFBLEVBQUEsQ0FBQTtBQUNBLHlCQUFBLEVBQUEsRUFBQTtpQkFDQSxDQUFBO2FBQ0EsQ0FBQSxDQUFBOztBQUVBLG9CQUFBLENBQUEsYUFBQSxDQUFBLEtBQUEsRUFBQTtBQUNBLDJCQUFBLEVBQUEsZ0JBQUE7QUFDQSx5QkFBQSxFQUFBLHNCQUFBO0FBQ0EseUJBQUEsRUFBQSxDQUFBO2FBQ0EsQ0FBQSxDQUFBO0FBQ0Esb0JBQUEsQ0FBQSxhQUFBLENBQUEsS0FBQSxFQUFBO0FBQ0EsMkJBQUEsRUFBQSxrQkFBQTtBQUNBLHlCQUFBLEVBQUEsd0JBQUE7QUFDQSx5QkFBQSxFQUFBLENBQUE7YUFDQSxDQUFBLENBQUE7O0FBRUEsb0JBQUEsQ0FBQSxRQUFBLENBQUEsUUFBQSxDQUFBLGNBQUEsQ0FBQSxPQUFBLENBQUEsRUFBQSxHQUFBLENBQUEsQ0FBQTtTQUNBO0tBQ0EsQ0FBQSxDQUFBO0NBQ0EsQ0FBQSxDQUFBOztBQzVFQSxHQUFBLENBQUEsTUFBQSxDQUFBLFVBQUEsY0FBQSxFQUFBO0FBQ0Esa0JBQUEsQ0FBQSxLQUFBLENBQUEsUUFBQSxFQUFBO0FBQ0EsV0FBQSxFQUFBLGNBQUE7QUFDQSxtQkFBQSxFQUFBLHVCQUFBO0FBQ0Esa0JBQUEsRUFBQSxvQkFBQSxNQUFBLEVBQUEsV0FBQSxFQUFBO0FBQ0Esa0JBQUEsQ0FBQSxXQUFBLEdBQUEsV0FBQSxDQUFBO1NBQ0E7QUFDQSxlQUFBLEVBQUE7Ozs7QUFJQSx1QkFBQSxFQUFBLHFCQUFBLFlBQUEsRUFBQTtBQUNBLHVCQUFBLFlBQUEsQ0FBQSxTQUFBLEVBQUEsQ0FBQTthQUNBO1NBQ0E7S0FDQSxDQUFBLENBQUE7Q0FDQSxDQUFBLENBQUE7O0FDaEJBLEdBQUEsQ0FBQSxNQUFBLENBQUEsVUFBQSxjQUFBLEVBQUE7QUFDQSxrQkFBQSxDQUFBLEtBQUEsQ0FBQSxPQUFBLEVBQUE7QUFDQSxXQUFBLEVBQUEsUUFBQTtBQUNBLG1CQUFBLEVBQUEscUJBQUE7QUFDQSxrQkFBQSxFQUFBLFdBQUE7S0FDQSxDQUFBLENBQUE7Q0FDQSxDQUFBLENBQUE7O0FBRUEsR0FBQSxDQUFBLFVBQUEsQ0FBQSxXQUFBLEVBQUEsVUFBQSxNQUFBLEVBQUEsV0FBQSxFQUFBLE1BQUEsRUFBQTs7QUFFQSxVQUFBLENBQUEsS0FBQSxHQUFBLEVBQUEsQ0FBQTtBQUNBLFVBQUEsQ0FBQSxLQUFBLEdBQUEsSUFBQSxDQUFBOztBQUVBLFVBQUEsQ0FBQSxTQUFBLEdBQUEsVUFBQSxTQUFBLEVBQUE7O0FBRUEsY0FBQSxDQUFBLEtBQUEsR0FBQSxJQUFBLENBQUE7O0FBRUEsbUJBQUEsQ0FBQSxLQUFBLENBQUEsU0FBQSxDQUFBLENBQUEsSUFBQSxDQUFBLFVBQUEsSUFBQSxFQUFBO0FBQ0EsZ0JBQUEsSUFBQSxDQUFBLE9BQUEsRUFBQSxNQUFBLENBQUEsRUFBQSxDQUFBLFdBQUEsRUFBQSxFQUFBLFFBQUEsRUFBQSxJQUFBLENBQUEsR0FBQSxFQUFBLENBQUEsQ0FBQSxLQUNBLE1BQUEsQ0FBQSxFQUFBLENBQUEsTUFBQSxDQUFBLENBQUE7U0FDQSxDQUFBLFNBQUEsQ0FBQSxZQUFBO0FBQ0Esa0JBQUEsQ0FBQSxLQUFBLEdBQUEsNEJBQUEsQ0FBQTtTQUNBLENBQUEsQ0FBQTtLQUNBLENBQUE7Q0FDQSxDQUFBLENBQUE7O0FDeEJBLEdBQUEsQ0FBQSxNQUFBLENBQUEsVUFBQSxjQUFBLEVBQUE7QUFDQSxrQkFBQSxDQUNBLEtBQUEsQ0FBQSxXQUFBLEVBQUE7QUFDQSxXQUFBLEVBQUEsZ0JBQUE7QUFDQSxtQkFBQSxFQUFBLDZCQUFBO0FBQ0Esa0JBQUEsRUFBQSxXQUFBO0tBQ0EsQ0FBQSxDQUFBO0NBQ0EsQ0FBQSxDQUFBOztBQUVBLEdBQUEsQ0FBQSxVQUFBLENBQUEsV0FBQSxFQUFBLFVBQUEsTUFBQSxFQUFBLFdBQUEsRUFBQSxZQUFBLEVBQUEsV0FBQSxFQUFBLE1BQUEsRUFBQTs7QUFFQSxVQUFBLENBQUEsU0FBQSxHQUFBLFVBQUEsT0FBQSxFQUFBO0FBQ0EsbUJBQUEsQ0FBQSxJQUFBLENBQUEsWUFBQSxDQUFBLE1BQUEsRUFBQSxFQUFBLFNBQUEsRUFBQSxLQUFBLEVBQUEsVUFBQSxFQUFBLE9BQUEsRUFBQSxDQUFBLENBQ0EsSUFBQSxDQUFBLFVBQUEsSUFBQSxFQUFBO0FBQ0EsdUJBQUEsQ0FBQSxLQUFBLENBQUEsRUFBQSxLQUFBLEVBQUEsSUFBQSxDQUFBLEtBQUEsRUFBQSxRQUFBLEVBQUEsT0FBQSxFQUFBLENBQUEsQ0FDQSxJQUFBLENBQUEsWUFBQTtBQUNBLHNCQUFBLENBQUEsRUFBQSxDQUFBLE1BQUEsQ0FBQSxDQUFBO2FBQ0EsQ0FBQSxDQUFBO1NBQ0EsQ0FBQSxDQUFBO0tBQ0EsQ0FBQTtDQUNBLENBQUEsQ0FBQTs7QUNwQkEsR0FBQSxDQUFBLE1BQUEsQ0FBQSxVQUFBLGNBQUEsRUFBQTs7QUFFQSxrQkFBQSxDQUFBLEtBQUEsQ0FBQSxRQUFBLEVBQUE7QUFDQSxXQUFBLEVBQUEsU0FBQTtBQUNBLG1CQUFBLEVBQUEsdUJBQUE7QUFDQSxrQkFBQSxFQUFBLFlBQUE7S0FDQSxDQUFBLENBQUE7Q0FFQSxDQUFBLENBQUE7O0FBRUEsR0FBQSxDQUFBLFVBQUEsQ0FBQSxZQUFBLEVBQUEsVUFBQSxNQUFBLEVBQUEsV0FBQSxFQUFBLE1BQUEsRUFBQTs7QUFFQSxVQUFBLENBQUEsS0FBQSxHQUFBLElBQUEsQ0FBQTs7QUFFQSxVQUFBLENBQUEsVUFBQSxHQUFBLFVBQUEsVUFBQSxFQUFBO0FBQ0EsY0FBQSxDQUFBLEtBQUEsR0FBQSxJQUFBLENBQUE7QUFDQSxtQkFBQSxDQUFBLE1BQUEsQ0FBQSxVQUFBLENBQUEsQ0FDQSxJQUFBLENBQUEsWUFBQTtBQUNBLGtCQUFBLENBQUEsRUFBQSxDQUFBLE1BQUEsQ0FBQSxDQUFBO1NBQ0EsQ0FBQSxTQUNBLENBQUEsWUFBQTtBQUNBLGtCQUFBLENBQUEsS0FBQSxHQUFBLGlCQUFBLENBQUE7U0FDQSxDQUFBLENBQUE7S0FFQSxDQUFBO0NBRUEsQ0FBQSxDQUFBOztBQzFCQSxHQUFBLENBQUEsTUFBQSxDQUFBLFVBQUEsY0FBQSxFQUFBO0FBQ0Esa0JBQUEsQ0FDQSxLQUFBLENBQUEsTUFBQSxFQUFBO0FBQ0EsV0FBQSxFQUFBLGVBQUE7QUFDQSxtQkFBQSxFQUFBLG9CQUFBO0FBQ0Esa0JBQUEsRUFBQSxvQkFBQSxNQUFBLEVBQUEsUUFBQSxFQUFBO0FBQ0Esa0JBQUEsQ0FBQSxJQUFBLEdBQUEsUUFBQSxDQUFBO1NBQ0E7QUFDQSxlQUFBLEVBQUE7QUFDQSxvQkFBQSxFQUFBLGtCQUFBLFlBQUEsRUFBQSxXQUFBLEVBQUE7QUFDQSx1QkFBQSxXQUFBLENBQUEsT0FBQSxDQUFBLFlBQUEsQ0FBQSxNQUFBLENBQUEsQ0FDQSxJQUFBLENBQUEsVUFBQSxJQUFBLEVBQUE7QUFDQSwyQkFBQSxJQUFBLENBQUE7aUJBQ0EsQ0FBQSxDQUFBO2FBQ0E7U0FDQTtLQUNBLENBQUEsQ0FBQTtDQUNBLENBQUEsQ0FBQTs7QUNqQkEsR0FBQSxDQUFBLE1BQUEsQ0FBQSxVQUFBLGNBQUEsRUFBQTtBQUNBLGtCQUFBLENBQUEsS0FBQSxDQUFBLE9BQUEsRUFBQTtBQUNBLFdBQUEsRUFBQSxRQUFBO0FBQ0EsbUJBQUEsRUFBQSxzQkFBQTtBQUNBLGVBQUEsRUFBQTtBQUNBLGlCQUFBLEVBQUEsZUFBQSxXQUFBLEVBQUE7QUFDQSx1QkFBQSxXQUFBLENBQUEsTUFBQSxFQUFBLENBQUE7YUFDQTtTQUNBO0FBQ0Esa0JBQUEsRUFBQSxvQkFBQSxNQUFBLEVBQUEsS0FBQSxFQUFBLE9BQUEsRUFBQSxNQUFBLEVBQUE7QUFDQSxrQkFBQSxDQUFBLEtBQUEsR0FBQSxLQUFBLENBQUE7Ozs7OztTQU1BO0tBQ0EsQ0FBQSxDQUFBO0NBQ0EsQ0FBQSxDQUFBOztBQ2xCQSxHQUFBLENBQUEsT0FBQSxDQUFBLGNBQUEsRUFBQSxVQUFBLEtBQUEsRUFBQTtBQUNBLFFBQUEsTUFBQSxHQUFBLFNBQUEsTUFBQSxDQUFBLEtBQUEsRUFBQTtBQUNBLGVBQUEsQ0FBQSxNQUFBLENBQUEsSUFBQSxFQUFBLEtBQUEsQ0FBQSxDQUFBO0tBQ0EsQ0FBQTs7QUFFQSxVQUFBLENBQUEsTUFBQSxHQUFBLFlBQUE7QUFDQSxlQUFBLEtBQUEsQ0FBQSxHQUFBLENBQUEsV0FBQSxDQUFBLENBQ0EsSUFBQSxDQUFBLFVBQUEsUUFBQSxFQUFBO0FBQ0EsbUJBQUEsUUFBQSxDQUFBLElBQUEsQ0FBQTtTQUNBLENBQUEsQ0FBQTtLQUNBLENBQUE7O0FBRUEsVUFBQSxDQUFBLFNBQUEsR0FBQSxZQUFBO0FBQ0EsZUFBQSxLQUFBLENBQUEsR0FBQSxDQUFBLGtCQUFBLENBQUEsQ0FDQSxJQUFBLENBQUEsVUFBQSxRQUFBLEVBQUE7QUFDQSxtQkFBQSxRQUFBLENBQUEsSUFBQSxDQUFBO1NBQ0EsQ0FBQSxDQUFBO0tBQ0EsQ0FBQTs7QUFFQSxXQUFBLE1BQUEsQ0FBQTtDQUNBLENBQUEsQ0FBQTs7QUNwQkEsR0FBQSxDQUFBLE9BQUEsQ0FBQSxhQUFBLEVBQUEsVUFBQSxLQUFBLEVBQUE7O0FBRUEsUUFBQSxJQUFBLEdBQUEsU0FBQSxJQUFBLENBQUEsS0FBQSxFQUFBO0FBQ0EsZUFBQSxDQUFBLE1BQUEsQ0FBQSxJQUFBLEVBQUEsS0FBQSxDQUFBLENBQUE7S0FDQSxDQUFBOztBQUVBLFFBQUEsQ0FBQSxNQUFBLEdBQUEsWUFBQTtBQUNBLGVBQUEsS0FBQSxDQUFBLEdBQUEsQ0FBQSxZQUFBLENBQUEsQ0FDQSxJQUFBLENBQUEsVUFBQSxRQUFBLEVBQUE7QUFDQSxtQkFBQSxRQUFBLENBQUEsSUFBQSxDQUFBO1NBQ0EsQ0FBQSxDQUFBO0tBQ0EsQ0FBQTs7QUFFQSxRQUFBLENBQUEsT0FBQSxHQUFBLFVBQUEsRUFBQSxFQUFBO0FBQ0EsZUFBQSxLQUFBLENBQUEsR0FBQSxDQUFBLGFBQUEsR0FBQSxFQUFBLENBQUEsQ0FDQSxJQUFBLENBQUEsVUFBQSxRQUFBLEVBQUE7QUFDQSxtQkFBQSxRQUFBLENBQUEsSUFBQSxDQUFBO1NBQ0EsQ0FBQSxDQUFBO0tBQ0EsQ0FBQTs7QUFFQSxRQUFBLENBQUEsSUFBQSxHQUFBLFVBQUEsRUFBQSxFQUFBLEtBQUEsRUFBQTtBQUNBLGVBQUEsS0FBQSxDQUFBLEdBQUEsQ0FBQSxhQUFBLEdBQUEsRUFBQSxFQUFBLEtBQUEsQ0FBQSxDQUNBLElBQUEsQ0FBQSxVQUFBLFFBQUEsRUFBQTtBQUNBLG1CQUFBLFFBQUEsQ0FBQSxJQUFBLENBQUE7U0FDQSxDQUFBLENBQUE7S0FDQSxDQUFBOztBQUVBLFFBQUEsVUFBQSxHQUFBLFVBQUEsRUFBQSxFQUFBO0FBQ0EsZUFBQSxLQUFBLFVBQUEsQ0FBQSxhQUFBLEdBQUEsRUFBQSxDQUFBLENBQ0EsSUFBQSxDQUFBLFVBQUEsUUFBQSxFQUFBO0FBQ0EsbUJBQUEsUUFBQSxDQUFBLElBQUEsQ0FBQTtTQUNBLENBQUEsQ0FBQTtLQUNBLENBQUE7O0FBR0EsV0FBQSxJQUFBLENBQUE7Q0FDQSxDQUFBLENBQUE7O0FDcENBLEdBQUEsQ0FBQSxTQUFBLENBQUEsV0FBQSxFQUFBLFlBQUE7QUFDQSxXQUFBO0FBQ0EsZ0JBQUEsRUFBQSxHQUFBO0FBQ0EsbUJBQUEsRUFBQSw2Q0FBQTtLQUNBLENBQUE7Q0FDQSxDQUFBLENBQUE7O0FDTEEsR0FBQSxDQUFBLFNBQUEsQ0FBQSxRQUFBLEVBQUEsVUFBQSxVQUFBLEVBQUEsV0FBQSxFQUFBLFdBQUEsRUFBQSxNQUFBLEVBQUE7O0FBRUEsV0FBQTtBQUNBLGdCQUFBLEVBQUEsR0FBQTtBQUNBLGFBQUEsRUFBQSxFQUFBO0FBQ0EsbUJBQUEsRUFBQSx5Q0FBQTtBQUNBLFlBQUEsRUFBQSxjQUFBLEtBQUEsRUFBQTs7QUFFQSxpQkFBQSxDQUFBLEtBQUEsR0FBQSxDQUNBLEVBQUEsS0FBQSxFQUFBLE9BQUEsRUFBQSxLQUFBLEVBQUEsT0FBQSxFQUFBLEVBQ0EsRUFBQSxLQUFBLEVBQUEsTUFBQSxFQUFBLEtBQUEsRUFBQSxNQUFBLEVBQUEsRUFDQSxFQUFBLEtBQUEsRUFBQSxRQUFBLEVBQUEsS0FBQSxFQUFBLFFBQUEsRUFBQSxFQUNBLEVBQUEsS0FBQSxFQUFBLGVBQUEsRUFBQSxLQUFBLEVBQUEsTUFBQSxFQUFBLENBQ0EsQ0FBQTs7QUFFQSxpQkFBQSxDQUFBLElBQUEsR0FBQSxJQUFBLENBQUE7O0FBRUEsaUJBQUEsQ0FBQSxVQUFBLEdBQUEsWUFBQTtBQUNBLHVCQUFBLFdBQUEsQ0FBQSxlQUFBLEVBQUEsQ0FBQTthQUNBLENBQUE7O0FBRUEsaUJBQUEsQ0FBQSxNQUFBLEdBQUEsWUFBQTtBQUNBLDJCQUFBLENBQUEsTUFBQSxFQUFBLENBQUEsSUFBQSxDQUFBLFlBQUE7QUFDQSwwQkFBQSxDQUFBLEVBQUEsQ0FBQSxNQUFBLENBQUEsQ0FBQTtpQkFDQSxDQUFBLENBQUE7YUFDQSxDQUFBOztBQUVBLGdCQUFBLE9BQUEsR0FBQSxTQUFBLE9BQUEsR0FBQTtBQUNBLDJCQUFBLENBQUEsZUFBQSxFQUFBLENBQUEsSUFBQSxDQUFBLFVBQUEsSUFBQSxFQUFBO0FBQ0EseUJBQUEsQ0FBQSxJQUFBLEdBQUEsSUFBQSxDQUFBO2lCQUNBLENBQUEsQ0FBQTthQUNBLENBQUE7O0FBRUEsZ0JBQUEsVUFBQSxHQUFBLFNBQUEsVUFBQSxHQUFBO0FBQ0EscUJBQUEsQ0FBQSxJQUFBLEdBQUEsSUFBQSxDQUFBO2FBQ0EsQ0FBQTs7QUFFQSxtQkFBQSxFQUFBLENBQUE7O0FBRUEsc0JBQUEsQ0FBQSxHQUFBLENBQUEsV0FBQSxDQUFBLFlBQUEsRUFBQSxPQUFBLENBQUEsQ0FBQTtBQUNBLHNCQUFBLENBQUEsR0FBQSxDQUFBLFdBQUEsQ0FBQSxhQUFBLEVBQUEsT0FBQSxDQUFBLENBQUE7QUFDQSxzQkFBQSxDQUFBLEdBQUEsQ0FBQSxXQUFBLENBQUEsYUFBQSxFQUFBLFVBQUEsQ0FBQSxDQUFBO0FBQ0Esc0JBQUEsQ0FBQSxHQUFBLENBQUEsV0FBQSxDQUFBLGNBQUEsRUFBQSxVQUFBLENBQUEsQ0FBQTtTQUVBOztLQUVBLENBQUE7Q0FFQSxDQUFBLENBQUE7O0FDaERBLEdBQUEsQ0FBQSxTQUFBLENBQUEsWUFBQSxFQUFBLFlBQUE7QUFDQSxXQUFBO0FBQ0EsZ0JBQUEsRUFBQSxJQUFBO0FBQ0EsbUJBQUEsRUFBQSxtREFBQTtLQUNBLENBQUE7Q0FDQSxDQUFBLENBQUE7O0FDTEEsR0FBQSxDQUFBLFNBQUEsQ0FBQSxZQUFBLEVBQUEsVUFBQSxXQUFBLEVBQUEsWUFBQSxFQUFBLE1BQUEsRUFBQSxPQUFBLEVBQUE7QUFDQSxXQUFBO0FBQ0EsZ0JBQUEsRUFBQSxHQUFBO0FBQ0EsbUJBQUEsRUFBQSx5REFBQTtBQUNBLFlBQUEsRUFBQSxjQUFBLEtBQUEsRUFBQTtBQUNBLGlCQUFBLENBQUEsUUFBQSxHQUFBLElBQUEsQ0FBQTtBQUNBLGlCQUFBLENBQUEsT0FBQSxHQUFBLE9BQUEsQ0FBQSxJQUFBLENBQUEsT0FBQSxDQUFBO0FBQ0EsaUJBQUEsQ0FBQSxRQUFBLEdBQUEsS0FBQSxDQUFBOztBQUVBLGlCQUFBLENBQUEsVUFBQSxHQUFBLFlBQUE7QUFDQSxxQkFBQSxDQUFBLE1BQUEsR0FBQSxPQUFBLENBQUEsSUFBQSxDQUFBLEtBQUEsQ0FBQSxJQUFBLENBQUEsQ0FBQTtBQUNBLHFCQUFBLENBQUEsUUFBQSxHQUFBLElBQUEsQ0FBQTthQUNBLENBQUE7QUFDQSxpQkFBQSxDQUFBLFVBQUEsR0FBQSxZQUFBO0FBQ0EscUJBQUEsQ0FBQSxJQUFBLEdBQUEsT0FBQSxDQUFBLElBQUEsQ0FBQSxLQUFBLENBQUEsTUFBQSxDQUFBLENBQUE7QUFDQSxxQkFBQSxDQUFBLFFBQUEsR0FBQSxLQUFBLENBQUE7YUFDQSxDQUFBO0FBQ0EsaUJBQUEsQ0FBQSxRQUFBLEdBQUEsVUFBQSxJQUFBLEVBQUE7QUFDQSwyQkFBQSxDQUFBLElBQUEsQ0FBQSxJQUFBLENBQUEsR0FBQSxFQUFBLElBQUEsQ0FBQSxDQUNBLElBQUEsQ0FBQSxVQUFBLFdBQUEsRUFBQTtBQUNBLHlCQUFBLENBQUEsSUFBQSxHQUFBLFdBQUEsQ0FBQTtBQUNBLHlCQUFBLENBQUEsUUFBQSxHQUFBLEtBQUEsQ0FBQTtpQkFDQSxDQUFBLENBQUE7YUFDQSxDQUFBO0FBQ0EsaUJBQUEsQ0FBQSxVQUFBLEdBQUEsVUFBQSxJQUFBLEVBQUE7QUFDQSwyQkFBQSxVQUFBLENBQUEsSUFBQSxDQUFBLENBQ0EsSUFBQSxDQUFBLFlBQUE7QUFDQSx5QkFBQSxDQUFBLFFBQUEsR0FBQSxLQUFBLENBQUE7QUFDQSwwQkFBQSxDQUFBLEVBQUEsQ0FBQSxNQUFBLENBQUEsQ0FBQTtpQkFDQSxDQUFBLENBQUE7YUFDQSxDQUFBOztBQUVBLGlCQUFBLENBQUEsU0FBQSxHQUFBLFVBQUEsRUFBQSxFQUFBO0FBQ0EsMkJBQUEsQ0FBQSxJQUFBLENBQUEsRUFBQSxFQUFBLEVBQUEsU0FBQSxFQUFBLElBQUEsRUFBQSxDQUFBLENBQ0EsSUFBQSxDQUFBLFlBQUE7O0FBRUEseUJBQUEsQ0FBQSxRQUFBLEdBQUEsS0FBQSxDQUFBO2lCQUNBLENBQUEsQ0FBQTthQUNBLENBQUE7U0FDQTtBQUNBLGFBQUEsRUFBQTtBQUNBLGdCQUFBLEVBQUEsR0FBQTtTQUNBO0tBQ0EsQ0FBQTtDQUNBLENBQUEsQ0FBQTs7QUM1Q0EsR0FBQSxDQUFBLFNBQUEsQ0FBQSxVQUFBLEVBQUEsWUFBQTtBQUNBLFdBQUE7QUFDQSxnQkFBQSxFQUFBLEdBQUE7QUFDQSxtQkFBQSxFQUFBLHFEQUFBO0tBQ0EsQ0FBQTtDQUNBLENBQUEsQ0FBQSIsImZpbGUiOiJtYWluLmpzIiwic291cmNlc0NvbnRlbnQiOlsiJ3VzZSBzdHJpY3QnO1xud2luZG93LmFwcCA9IGFuZ3VsYXIubW9kdWxlKCdGdWxsc3RhY2tHZW5lcmF0ZWRBcHAnLCBbJ3VpLnJvdXRlcicsICd1aS5ib290c3RyYXAnLCAnZnNhUHJlQnVpbHQnXSk7XG5cbmFwcC5jb25maWcoZnVuY3Rpb24gKCR1cmxSb3V0ZXJQcm92aWRlciwgJGxvY2F0aW9uUHJvdmlkZXIpIHtcblxuXHQvLyB0aGlzIG1ha2VzIHRoZSAnL3VzZXJzLycgcm91dGUgY29ycmVjdGx5IHJlZGlyZWN0IHRvICcvdXNlcnMnXG5cdCR1cmxSb3V0ZXJQcm92aWRlci5ydWxlKGZ1bmN0aW9uICgkaW5qZWN0b3IsICRsb2NhdGlvbikge1xuXG5cdFx0dmFyIHJlID0gLyguKykoXFwvKykoXFw/LiopPyQvXG5cdFx0dmFyIHBhdGggPSAkbG9jYXRpb24udXJsKCk7XG5cblx0XHRpZihyZS50ZXN0KHBhdGgpKSB7XG5cdFx0XHRyZXR1cm4gcGF0aC5yZXBsYWNlKHJlLCAnJDEkMycpXG5cdFx0fVxuXG5cdFx0cmV0dXJuIGZhbHNlO1xuXHR9KTtcblx0Ly8gVGhpcyB0dXJucyBvZmYgaGFzaGJhbmcgdXJscyAoLyNhYm91dCkgYW5kIGNoYW5nZXMgaXQgdG8gc29tZXRoaW5nIG5vcm1hbCAoL2Fib3V0KVxuXHQkbG9jYXRpb25Qcm92aWRlci5odG1sNU1vZGUodHJ1ZSk7XG5cdCR1cmxSb3V0ZXJQcm92aWRlci53aGVuKCcvYXV0aC86cHJvdmlkZXInLCBmdW5jdGlvbiAoKSB7XG5cdFx0d2luZG93LmxvY2F0aW9uLnJlbG9hZCgpO1xuXHR9KTtcblx0Ly8gSWYgd2UgZ28gdG8gYSBVUkwgdGhhdCB1aS1yb3V0ZXIgZG9lc24ndCBoYXZlIHJlZ2lzdGVyZWQsIGdvIHRvIHRoZSBcIi9cIiB1cmwuXG5cdCR1cmxSb3V0ZXJQcm92aWRlci5vdGhlcndpc2UoJy8nKTtcblxufSk7XG5cbi8vIFRoaXMgYXBwLnJ1biBpcyBmb3IgY29udHJvbGxpbmcgYWNjZXNzIHRvIHNwZWNpZmljIHN0YXRlcy5cbmFwcC5ydW4oZnVuY3Rpb24gKCRyb290U2NvcGUsIEF1dGhTZXJ2aWNlLCAkc3RhdGUpIHtcblxuXHQvLyBUaGUgZ2l2ZW4gc3RhdGUgcmVxdWlyZXMgYW4gYXV0aGVudGljYXRlZCB1c2VyLlxuXHR2YXIgZGVzdGluYXRpb25TdGF0ZVJlcXVpcmVzQXV0aCA9IGZ1bmN0aW9uIChzdGF0ZSkge1xuXHRcdHJldHVybiBzdGF0ZS5kYXRhICYmIHN0YXRlLmRhdGEuYXV0aGVudGljYXRlO1xuXHR9O1xuXG5cdC8vICRzdGF0ZUNoYW5nZVN0YXJ0IGlzIGFuIGV2ZW50IGZpcmVkXG5cdC8vIHdoZW5ldmVyIHRoZSBwcm9jZXNzIG9mIGNoYW5naW5nIGEgc3RhdGUgYmVnaW5zLlxuXHQkcm9vdFNjb3BlLiRvbignJHN0YXRlQ2hhbmdlU3RhcnQnLCBmdW5jdGlvbiAoZXZlbnQsIHRvU3RhdGUsIHRvUGFyYW1zKSB7XG5cblx0XHRpZiAoIWRlc3RpbmF0aW9uU3RhdGVSZXF1aXJlc0F1dGgodG9TdGF0ZSkpIHtcblx0XHRcdC8vIFRoZSBkZXN0aW5hdGlvbiBzdGF0ZSBkb2VzIG5vdCByZXF1aXJlIGF1dGhlbnRpY2F0aW9uXG5cdFx0XHQvLyBTaG9ydCBjaXJjdWl0IHdpdGggcmV0dXJuLlxuXHRcdFx0cmV0dXJuO1xuXHRcdH1cblxuXHRcdGlmIChBdXRoU2VydmljZS5pc0F1dGhlbnRpY2F0ZWQoKSkge1xuXHRcdFx0Ly8gVGhlIHVzZXIgaXMgYXV0aGVudGljYXRlZC5cblx0XHRcdC8vIFNob3J0IGNpcmN1aXQgd2l0aCByZXR1cm4uXG5cdFx0XHRyZXR1cm47XG5cdFx0fVxuXG5cdFx0Ly8gQ2FuY2VsIG5hdmlnYXRpbmcgdG8gbmV3IHN0YXRlLlxuXHRcdGV2ZW50LnByZXZlbnREZWZhdWx0KCk7XG5cblx0XHRBdXRoU2VydmljZS5nZXRMb2dnZWRJblVzZXIoKS50aGVuKGZ1bmN0aW9uICh1c2VyKSB7XG5cdFx0XHQvLyBJZiBhIHVzZXIgaXMgcmV0cmlldmVkLCB0aGVuIHJlbmF2aWdhdGUgdG8gdGhlIGRlc3RpbmF0aW9uXG5cdFx0XHQvLyAodGhlIHNlY29uZCB0aW1lLCBBdXRoU2VydmljZS5pc0F1dGhlbnRpY2F0ZWQoKSB3aWxsIHdvcmspXG5cdFx0XHQvLyBvdGhlcndpc2UsIGlmIG5vIHVzZXIgaXMgbG9nZ2VkIGluLCBnbyB0byBcImxvZ2luXCIgc3RhdGUuXG5cdFx0XHRpZiAodXNlcikge1xuXHRcdFx0XHQkc3RhdGUuZ28odG9TdGF0ZS5uYW1lLCB0b1BhcmFtcyk7XG5cdFx0XHR9IGVsc2Uge1xuXHRcdFx0XHQkc3RhdGUuZ28oJ2xvZ2luJyk7XG5cdFx0XHR9XG5cdFx0fSk7XG5cblx0fSk7XG5cbn0pO1xuIiwiYXBwLmNvbmZpZyhmdW5jdGlvbiAoJHN0YXRlUHJvdmlkZXIpIHtcbiAgICAkc3RhdGVQcm92aWRlclxuICAgIC5zdGF0ZSgnZGF0YScsIHtcbiAgICAgICAgdXJsOiAnL2RhdGEnLFxuICAgICAgICB0ZW1wbGF0ZVVybDogJ2pzL2RhdGEvZGF0YS5odG1sJyxcbiAgICAgICAgY29udHJvbGxlcjogZnVuY3Rpb24gKCRzY29wZSwgYWxsRHdlZXRzKSB7XG4gICAgICAgICAgJHNjb3BlLmR3ZWV0cyA9IGFsbER3ZWV0cztcbiAgICAgICAgfSxcbiAgICAgICAgcmVzb2x2ZToge1xuICAgICAgICAgICAgLy8gZmluZER3ZWV0czogZnVuY3Rpb24gKER3ZWV0RmFjdG9yeSkge1xuICAgICAgICAgICAgLy8gICAgIHJldHVybiBEd2VldEZhY3RvcnkuZ2V0QWxsKCk7XG4gICAgICAgICAgICAvLyB9O1xuICAgICAgICAgICAgYWxsRHdlZXRzOiBmdW5jdGlvbiAoRHdlZXRGYWN0b3J5KSB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIER3ZWV0RmFjdG9yeS5nZXRBbGwoKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgIH0pXG59KTtcbiIsImFwcC5jb25maWcoZnVuY3Rpb24gKCRzdGF0ZVByb3ZpZGVyKSB7XG4gICAgJHN0YXRlUHJvdmlkZXIuc3RhdGUoJ2RvY3MnLCB7XG4gICAgICAgIHVybDogJy9kb2NzJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6ICdqcy9kb2NzL2RvY3MuaHRtbCdcbiAgICB9KTtcbn0pO1xuIiwiKGZ1bmN0aW9uICgpIHtcblxuICAgICd1c2Ugc3RyaWN0JztcblxuICAgIC8vIEhvcGUgeW91IGRpZG4ndCBmb3JnZXQgQW5ndWxhciEgRHVoLWRveS5cbiAgICBpZiAoIXdpbmRvdy5hbmd1bGFyKSB0aHJvdyBuZXcgRXJyb3IoJ0kgY2FuXFwndCBmaW5kIEFuZ3VsYXIhJyk7XG5cbiAgICB2YXIgYXBwID0gYW5ndWxhci5tb2R1bGUoJ2ZzYVByZUJ1aWx0JywgW10pO1xuXG4gICAgYXBwLmZhY3RvcnkoJ1NvY2tldCcsIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgaWYgKCF3aW5kb3cuaW8pIHRocm93IG5ldyBFcnJvcignc29ja2V0LmlvIG5vdCBmb3VuZCEnKTtcbiAgICAgICAgcmV0dXJuIHdpbmRvdy5pbyh3aW5kb3cubG9jYXRpb24ub3JpZ2luKTtcbiAgICB9KTtcblxuICAgIC8vIEFVVEhfRVZFTlRTIGlzIHVzZWQgdGhyb3VnaG91dCBvdXIgYXBwIHRvXG4gICAgLy8gYnJvYWRjYXN0IGFuZCBsaXN0ZW4gZnJvbSBhbmQgdG8gdGhlICRyb290U2NvcGVcbiAgICAvLyBmb3IgaW1wb3J0YW50IGV2ZW50cyBhYm91dCBhdXRoZW50aWNhdGlvbiBmbG93LlxuICAgIGFwcC5jb25zdGFudCgnQVVUSF9FVkVOVFMnLCB7XG4gICAgICAgIGxvZ2luU3VjY2VzczogJ2F1dGgtbG9naW4tc3VjY2VzcycsXG4gICAgICAgIGxvZ2luRmFpbGVkOiAnYXV0aC1sb2dpbi1mYWlsZWQnLFxuICAgICAgICBzaWdudXBTdWNjZXNzOiAnYXV0aC1zaWdudXAtc3VjY2VzcycsXG4gICAgICAgIHNpZ251cEZhaWxlZDogJ2F1dGgtc2lnbnVwLWZhaWxlZCcsXG4gICAgICAgIGxvZ291dFN1Y2Nlc3M6ICdhdXRoLWxvZ291dC1zdWNjZXNzJyxcbiAgICAgICAgc2Vzc2lvblRpbWVvdXQ6ICdhdXRoLXNlc3Npb24tdGltZW91dCcsXG4gICAgICAgIG5vdEF1dGhlbnRpY2F0ZWQ6ICdhdXRoLW5vdC1hdXRoZW50aWNhdGVkJyxcbiAgICAgICAgbm90QXV0aG9yaXplZDogJ2F1dGgtbm90LWF1dGhvcml6ZWQnXG4gICAgfSk7XG5cbiAgICBhcHAuZmFjdG9yeSgnQXV0aEludGVyY2VwdG9yJywgZnVuY3Rpb24gKCRyb290U2NvcGUsICRxLCBBVVRIX0VWRU5UUykge1xuICAgICAgICB2YXIgc3RhdHVzRGljdCA9IHtcbiAgICAgICAgICAgIDQwMTogQVVUSF9FVkVOVFMubm90QXV0aGVudGljYXRlZCxcbiAgICAgICAgICAgIDQwMzogQVVUSF9FVkVOVFMubm90QXV0aG9yaXplZCxcbiAgICAgICAgICAgIDQxOTogQVVUSF9FVkVOVFMuc2Vzc2lvblRpbWVvdXQsXG4gICAgICAgICAgICA0NDA6IEFVVEhfRVZFTlRTLnNlc3Npb25UaW1lb3V0XG4gICAgICAgIH07XG4gICAgICAgIHJldHVybiB7XG4gICAgICAgICAgICByZXNwb25zZUVycm9yOiBmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgICAgICAgICAkcm9vdFNjb3BlLiRicm9hZGNhc3Qoc3RhdHVzRGljdFtyZXNwb25zZS5zdGF0dXNdLCByZXNwb25zZSk7XG4gICAgICAgICAgICAgICAgcmV0dXJuICRxLnJlamVjdChyZXNwb25zZSlcbiAgICAgICAgICAgIH1cbiAgICAgICAgfTtcbiAgICB9KTtcblxuICAgIGFwcC5jb25maWcoZnVuY3Rpb24gKCRodHRwUHJvdmlkZXIpIHtcbiAgICAgICAgJGh0dHBQcm92aWRlci5pbnRlcmNlcHRvcnMucHVzaChbXG4gICAgICAgICAgICAnJGluamVjdG9yJyxcbiAgICAgICAgICAgIGZ1bmN0aW9uICgkaW5qZWN0b3IpIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gJGluamVjdG9yLmdldCgnQXV0aEludGVyY2VwdG9yJyk7XG4gICAgICAgICAgICB9XG4gICAgICAgIF0pO1xuICAgIH0pO1xuXG4gICAgYXBwLnNlcnZpY2UoJ0F1dGhTZXJ2aWNlJywgZnVuY3Rpb24gKCRodHRwLCBTZXNzaW9uLCAkcm9vdFNjb3BlLCBBVVRIX0VWRU5UUywgJHEpIHtcblxuICAgICAgICBmdW5jdGlvbiBvblN1Y2Nlc3NmdWxMb2dpbihyZXNwb25zZSkge1xuICAgICAgICAgICAgdmFyIGRhdGEgPSByZXNwb25zZS5kYXRhO1xuICAgICAgICAgICAgU2Vzc2lvbi5jcmVhdGUoZGF0YS5pZCwgZGF0YS51c2VyKTtcbiAgICAgICAgICAgICRyb290U2NvcGUuJGJyb2FkY2FzdChBVVRIX0VWRU5UUy5sb2dpblN1Y2Nlc3MpO1xuICAgICAgICAgICAgcmV0dXJuIGRhdGEudXNlcjtcbiAgICAgICAgfVxuXG4gICAgICAgIC8vYWRkIHN1Y2Nlc3NmdWwgc2lnbnVwXG4gICAgICAgIGZ1bmN0aW9uIG9uU3VjY2Vzc2Z1bFNpZ251cChyZXNwb25zZSkge1xuICAgICAgICAgICAgdmFyIGRhdGEgPSByZXNwb25zZS5kYXRhO1xuICAgICAgICAgICAgU2Vzc2lvbi5jcmVhdGUoZGF0YS5pZCwgZGF0YS51c2VyKTtcbiAgICAgICAgICAgICRyb290U2NvcGUuJGJyb2FkY2FzdChBVVRIX0VWRU5UUy5zaWdudXBTdWNjZXNzKTtcbiAgICAgICAgICAgIHJldHVybiBkYXRhLnVzZXI7XG4gICAgICAgIH1cblxuICAgICAgICAvLyBVc2VzIHRoZSBzZXNzaW9uIGZhY3RvcnkgdG8gc2VlIGlmIGFuXG4gICAgICAgIC8vIGF1dGhlbnRpY2F0ZWQgdXNlciBpcyBjdXJyZW50bHkgcmVnaXN0ZXJlZC5cbiAgICAgICAgdGhpcy5pc0F1dGhlbnRpY2F0ZWQgPSBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICByZXR1cm4gISFTZXNzaW9uLnVzZXI7XG4gICAgICAgIH07XG5cbiAgICAgICAgdGhpcy5nZXRMb2dnZWRJblVzZXIgPSBmdW5jdGlvbiAoZnJvbVNlcnZlcikge1xuXG4gICAgICAgICAgICAvLyBJZiBhbiBhdXRoZW50aWNhdGVkIHNlc3Npb24gZXhpc3RzLCB3ZVxuICAgICAgICAgICAgLy8gcmV0dXJuIHRoZSB1c2VyIGF0dGFjaGVkIHRvIHRoYXQgc2Vzc2lvblxuICAgICAgICAgICAgLy8gd2l0aCBhIHByb21pc2UuIFRoaXMgZW5zdXJlcyB0aGF0IHdlIGNhblxuICAgICAgICAgICAgLy8gYWx3YXlzIGludGVyZmFjZSB3aXRoIHRoaXMgbWV0aG9kIGFzeW5jaHJvbm91c2x5LlxuXG4gICAgICAgICAgICAvLyBPcHRpb25hbGx5LCBpZiB0cnVlIGlzIGdpdmVuIGFzIHRoZSBmcm9tU2VydmVyIHBhcmFtZXRlcixcbiAgICAgICAgICAgIC8vIHRoZW4gdGhpcyBjYWNoZWQgdmFsdWUgd2lsbCBub3QgYmUgdXNlZC5cblxuICAgICAgICAgICAgaWYgKHRoaXMuaXNBdXRoZW50aWNhdGVkKCkgJiYgZnJvbVNlcnZlciAhPT0gdHJ1ZSkge1xuICAgICAgICAgICAgICAgIHJldHVybiAkcS53aGVuKFNlc3Npb24udXNlcik7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIC8vIE1ha2UgcmVxdWVzdCBHRVQgL3Nlc3Npb24uXG4gICAgICAgICAgICAvLyBJZiBpdCByZXR1cm5zIGEgdXNlciwgY2FsbCBvblN1Y2Nlc3NmdWxMb2dpbiB3aXRoIHRoZSByZXNwb25zZS5cbiAgICAgICAgICAgIC8vIElmIGl0IHJldHVybnMgYSA0MDEgcmVzcG9uc2UsIHdlIGNhdGNoIGl0IGFuZCBpbnN0ZWFkIHJlc29sdmUgdG8gbnVsbC5cbiAgICAgICAgICAgIHJldHVybiAkaHR0cC5nZXQoJy9zZXNzaW9uJykudGhlbihvblN1Y2Nlc3NmdWxMb2dpbikuY2F0Y2goZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgIHJldHVybiBudWxsO1xuICAgICAgICAgICAgfSk7XG5cbiAgICAgICAgfTtcblxuICAgICAgICB0aGlzLmxvZ2luID0gZnVuY3Rpb24gKGNyZWRlbnRpYWxzKSB7XG4gICAgICAgICAgICByZXR1cm4gJGh0dHAucG9zdCgnL2xvZ2luJywgY3JlZGVudGlhbHMpXG4gICAgICAgICAgICAgICAgLnRoZW4ob25TdWNjZXNzZnVsTG9naW4pXG4gICAgICAgICAgICAgICAgLmNhdGNoKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuICRxLnJlamVjdCh7IG1lc3NhZ2U6ICdJbnZhbGlkIGxvZ2luIGNyZWRlbnRpYWxzLicgfSk7XG4gICAgICAgICAgICAgICAgfSk7XG4gICAgICAgIH07XG5cbiAgICAgICAgdGhpcy5sb2dvdXQgPSBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICByZXR1cm4gJGh0dHAuZ2V0KCcvbG9nb3V0JykudGhlbihmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAgICAgU2Vzc2lvbi5kZXN0cm95KCk7XG4gICAgICAgICAgICAgICAgJHJvb3RTY29wZS4kYnJvYWRjYXN0KEFVVEhfRVZFTlRTLmxvZ291dFN1Y2Nlc3MpO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgIH07XG5cbiAgICAgICAgdGhpcy5zaWdudXAgPSBmdW5jdGlvbiAoY3JlZGVudGlhbHMpIHtcbiAgICAgICAgICAgIHJldHVybiAkaHR0cC5wb3N0KCcvc2lnbnVwJywgY3JlZGVudGlhbHMpXG4gICAgICAgICAgICAgICAgLnRoZW4ob25TdWNjZXNzZnVsU2lnbnVwKTtcbiAgICAgICAgfTtcblxuXG4gICAgfSk7XG5cbiAgICBhcHAuc2VydmljZSgnU2Vzc2lvbicsIGZ1bmN0aW9uICgkcm9vdFNjb3BlLCBBVVRIX0VWRU5UUykge1xuXG4gICAgICAgIHZhciBzZWxmID0gdGhpcztcblxuICAgICAgICAkcm9vdFNjb3BlLiRvbihBVVRIX0VWRU5UUy5ub3RBdXRoZW50aWNhdGVkLCBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICBzZWxmLmRlc3Ryb3koKTtcbiAgICAgICAgfSk7XG5cbiAgICAgICAgJHJvb3RTY29wZS4kb24oQVVUSF9FVkVOVFMuc2Vzc2lvblRpbWVvdXQsIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgIHNlbGYuZGVzdHJveSgpO1xuICAgICAgICB9KTtcblxuICAgICAgICB0aGlzLmlkID0gbnVsbDtcbiAgICAgICAgdGhpcy51c2VyID0gbnVsbDtcblxuICAgICAgICB0aGlzLmNyZWF0ZSA9IGZ1bmN0aW9uIChzZXNzaW9uSWQsIHVzZXIpIHtcbiAgICAgICAgICAgIHRoaXMuaWQgPSBzZXNzaW9uSWQ7XG4gICAgICAgICAgICB0aGlzLnVzZXIgPSB1c2VyO1xuICAgICAgICB9O1xuXG4gICAgICAgIHRoaXMuZGVzdHJveSA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgIHRoaXMuaWQgPSBudWxsO1xuICAgICAgICAgICAgdGhpcy51c2VyID0gbnVsbDtcbiAgICAgICAgfTtcblxuICAgIH0pO1xuXG59KSgpO1xuIiwiYXBwLmNvbmZpZyhmdW5jdGlvbigkc3RhdGVQcm92aWRlcikge1xuICAgICRzdGF0ZVByb3ZpZGVyLnN0YXRlKCdob21lJywge1xuICAgICAgICB1cmw6ICcvJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6ICdqcy9ob21lL2hvbWUuaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6IGZ1bmN0aW9uKCRzY29wZSwgRHdlZXRGYWN0b3J5KSB7XG4gICAgICAgICAgICAvL0NyZWF0ZSBhcnJheSBvZiBsYXRlc3QgZHdlZXRzIHRvIGRpc3BsYXkgb24gaG9tZSBzdGF0ZVxuICAgICAgICAgICAgJHNjb3BlLmhvbWVEd2VldHMgPSBbXTtcblxuICAgICAgICAgICAgLy9Jbml0aWFsaXplIHdpdGggZmlyc3QgZHdlZXRcbiAgICAgICAgICAgIER3ZWV0RmFjdG9yeS5nZXRMYXRlc3QoKVxuICAgICAgICAgICAgLnRoZW4oZnVuY3Rpb24oZHdlZXQpe1xuICAgICAgICAgICAgICAgICRzY29wZS5wcmV2RHdlZXQgPSBkd2VldDtcbiAgICAgICAgICAgIH0pO1xuXG4gICAgICAgICAgICB2YXIgbGluZTEgPSBuZXcgVGltZVNlcmllcygpO1xuICAgICAgICAgICAgdmFyIGxpbmUyID0gbmV3IFRpbWVTZXJpZXMoKTtcblxuICAgICAgICAgICAgLy9DaGVjayBldmVyeSBoYWxmIHNlY29uZCB0byBzZWUgaWYgdGhlIGxhc3QgZHdlZXQgaXMgbmV3LCB0aGVuIHB1c2ggdG8gaG9tZUR3ZWV0cywgdGhlbiBwbG90XG4gICAgICAgICAgICBzZXRJbnRlcnZhbChmdW5jdGlvbigpIHtcbiAgICAgICAgICAgICAgICBEd2VldEZhY3RvcnkuZ2V0TGF0ZXN0KClcbiAgICAgICAgICAgICAgICAudGhlbihmdW5jdGlvbihkd2VldCl7XG4gICAgICAgICAgICAgICAgICAgICRzY29wZS5sYXN0RHdlZXQgPSBkd2VldDtcbiAgICAgICAgICAgICAgICB9KVxuICAgICAgICAgICAgICAgIC50aGVuKGZ1bmN0aW9uKCkge1xuICAgICAgICAgICAgICAgICAgICBpZiAoJHNjb3BlLnByZXZEd2VldC5jcmVhdGVkICE9ICRzY29wZS5sYXN0RHdlZXQuY3JlYXRlZClcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgJHNjb3BlLmhvbWVEd2VldHMucHVzaCgkc2NvcGUubGFzdER3ZWV0KTtcbiAgICAgICAgICAgICAgICAgICAgICAgICRzY29wZS5wcmV2RHdlZXQgPSAkc2NvcGUubGFzdER3ZWV0O1xuICAgICAgICAgICAgICAgICAgICAgICAgbGluZTEuYXBwZW5kKG5ldyBEYXRlKCkuZ2V0VGltZSgpLCAkc2NvcGUubGFzdER3ZWV0LmNvbnRlbnRbJ1RlbXBlcmF0dXJlJ10pO1xuICAgICAgICAgICAgICAgICAgICAgICAgLy9SYW5kb20gcGxvdCB0byBjaGVjayB0aGF0IHRoZSBncmFwaCBpcyB3b3JraW5nXG4gICAgICAgICAgICAgICAgICAgICAgICBsaW5lMi5hcHBlbmQobmV3IERhdGUoKS5nZXRUaW1lKCksIE1hdGguZmxvb3IoTWF0aC5yYW5kb20oKSozKzcyKSk7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9KVxuXG4gICAgICAgICAgICB9LCAxMDApO1xuXG4gICAgICAgICAgICAvL01ha2UgYSBzbW9vdGhpZSBjaGFydCB3aXRoIGFlc3RoZXRpY2FsbHkgcGxlYXNpbmcgcHJvcGVydGllc1xuICAgICAgICAgICAgdmFyIHNtb290aGllID0gbmV3IFNtb290aGllQ2hhcnQoe1xuICAgICAgICAgICAgICAgIGdyaWQ6IHtcbiAgICAgICAgICAgICAgICAgICAgc3Ryb2tlU3R5bGU6ICdyZ2IoNjMsIDE2MCwgMTgyKScsXG4gICAgICAgICAgICAgICAgICAgIGZpbGxTdHlsZTogJ3JnYig0LCA1LCA5MSknLFxuICAgICAgICAgICAgICAgICAgICBsaW5lV2lkdGg6IDEsXG4gICAgICAgICAgICAgICAgICAgIG1pbGxpc1BlckxpbmU6IDUwMCxcbiAgICAgICAgICAgICAgICAgICAgdmVydGljYWxTZWN0aW9uczogNFxuICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAgLy8gbWF4VmFsdWU6IDczLFxuICAgICAgICAgICAgICAgIC8vIG1pblZhbHVlOiA3MixcbiAgICAgICAgICAgICAgICBtYXhWYWx1ZVNjYWxlOiAxLjAwNSxcbiAgICAgICAgICAgICAgICBtaW5WYWx1ZVNjYWxlOiAxLjAwNSxcbiAgICAgICAgICAgICAgICB0aW1lc3RhbXBGb3JtYXR0ZXI6U21vb3RoaWVDaGFydC50aW1lRm9ybWF0dGVyLFxuICAgICAgICAgICAgICAgIC8vVGhlIHJhbmdlIG9mIGFjY2VwdGFibGUgdGVtcGVyYXR1cmVzIHNob3VsZCBiZSBiZWxvd1xuICAgICAgICAgICAgICAgIGhvcml6b250YWxMaW5lczpbe1xuICAgICAgICAgICAgICAgICAgICBjb2xvcjonIzg4MDAwMCcsXG4gICAgICAgICAgICAgICAgICAgIGxpbmVXaWR0aDoyLFxuICAgICAgICAgICAgICAgICAgICB2YWx1ZTo3M1xuICAgICAgICAgICAgICAgIH0sIHtcbiAgICAgICAgICAgICAgICAgICAgY29sb3I6JyM4ODAwMDAnLFxuICAgICAgICAgICAgICAgICAgICBsaW5lV2lkdGg6MixcbiAgICAgICAgICAgICAgICAgICAgdmFsdWU6NzJcbiAgICAgICAgICAgICAgICB9XVxuICAgICAgICAgICAgfSk7XG5cbiAgICAgICAgICAgIHNtb290aGllLmFkZFRpbWVTZXJpZXMobGluZTEsIHtcbiAgICAgICAgICAgICAgICBzdHJva2VTdHlsZTogJ3JnYigwLCAyNTUsIDApJyxcbiAgICAgICAgICAgICAgICBmaWxsU3R5bGU6ICdyZ2JhKDAsIDI1NSwgMCwgMC40KScsXG4gICAgICAgICAgICAgICAgbGluZVdpZHRoOiAzXG4gICAgICAgICAgICB9KTtcbiAgICAgICAgICAgIHNtb290aGllLmFkZFRpbWVTZXJpZXMobGluZTIsIHtcbiAgICAgICAgICAgICAgICBzdHJva2VTdHlsZTogJ3JnYigyNTUsIDAsIDI1NSknLFxuICAgICAgICAgICAgICAgIGZpbGxTdHlsZTogJ3JnYmEoMjU1LCAwLCAyNTUsIDAuMyknLFxuICAgICAgICAgICAgICAgIGxpbmVXaWR0aDogM1xuICAgICAgICAgICAgfSk7XG5cbiAgICAgICAgICAgIHNtb290aGllLnN0cmVhbVRvKGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKFwiY2hhcnRcIiksIDMwMCk7XG4gICAgICAgIH1cbiAgICB9KTtcbn0pO1xuIiwiYXBwLmNvbmZpZyhmdW5jdGlvbigkc3RhdGVQcm92aWRlcikge1xuICAgICRzdGF0ZVByb3ZpZGVyLnN0YXRlKCdsYXRlc3QnLCB7XG4gICAgICAgIHVybDogJy9kYXRhL2xhdGVzdCcsXG4gICAgICAgIHRlbXBsYXRlVXJsOiAnanMvbGF0ZXN0L2xhdGVzdC5odG1sJyxcbiAgICAgICAgY29udHJvbGxlcjogZnVuY3Rpb24gKCRzY29wZSwgbGF0ZXN0RHdlZXQpIHtcbiAgICAgICAgICAkc2NvcGUubGF0ZXN0RHdlZXQgPSBsYXRlc3REd2VldDtcbiAgICAgICAgfSxcbiAgICAgICAgcmVzb2x2ZToge1xuICAgICAgICAgICAgLy8gZmluZER3ZWV0czogZnVuY3Rpb24gKER3ZWV0RmFjdG9yeSkge1xuICAgICAgICAgICAgLy8gICAgIHJldHVybiBEd2VldEZhY3RvcnkuZ2V0QWxsKCk7XG4gICAgICAgICAgICAvLyB9O1xuICAgICAgICAgICAgbGF0ZXN0RHdlZXQ6IGZ1bmN0aW9uIChEd2VldEZhY3RvcnkpIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gRHdlZXRGYWN0b3J5LmdldExhdGVzdCgpO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgfSlcbn0pXG4iLCJhcHAuY29uZmlnKGZ1bmN0aW9uICgkc3RhdGVQcm92aWRlcikge1xuICAkc3RhdGVQcm92aWRlci5zdGF0ZSgnbG9naW4nLCB7XG4gICAgdXJsOiAnL2xvZ2luJyxcbiAgICB0ZW1wbGF0ZVVybDogJ2pzL2xvZ2luL2xvZ2luLmh0bWwnLFxuICAgIGNvbnRyb2xsZXI6ICdMb2dpbkN0cmwnXG4gIH0pO1xufSk7XG5cbmFwcC5jb250cm9sbGVyKCdMb2dpbkN0cmwnLCBmdW5jdGlvbiAoJHNjb3BlLCBBdXRoU2VydmljZSwgJHN0YXRlKSB7XG5cbiAgJHNjb3BlLmxvZ2luID0ge307XG4gICRzY29wZS5lcnJvciA9IG51bGw7XG5cbiAgJHNjb3BlLnNlbmRMb2dpbiA9IGZ1bmN0aW9uIChsb2dpbkluZm8pIHtcblxuICAgICRzY29wZS5lcnJvciA9IG51bGw7XG5cbiAgICBBdXRoU2VydmljZS5sb2dpbihsb2dpbkluZm8pLnRoZW4oZnVuY3Rpb24gKHVzZXIpIHtcbiAgICAgICAgaWYodXNlci5uZXdQYXNzKSAkc3RhdGUuZ28oJ3Jlc2V0UGFzcycsIHsndXNlcklkJzogdXNlci5faWR9KTtcbiAgICAgIGVsc2UgJHN0YXRlLmdvKCdob21lJyk7XG4gICAgfSkuY2F0Y2goZnVuY3Rpb24gKCkge1xuICAgICAgJHNjb3BlLmVycm9yID0gJ0ludmFsaWQgbG9naW4gY3JlZGVudGlhbHMuJztcbiAgICB9KTtcbiAgfTtcbn0pO1xuIiwiYXBwLmNvbmZpZyhmdW5jdGlvbiAoJHN0YXRlUHJvdmlkZXIpIHtcbiAgICAkc3RhdGVQcm92aWRlclxuICAgIC5zdGF0ZSgncmVzZXRQYXNzJywge1xuICAgICAgICB1cmw6ICcvcmVzZXQvOnVzZXJJZCcsXG4gICAgICAgIHRlbXBsYXRlVXJsOiAnanMvcmVzZXRQYXNzL3Jlc2V0UGFzcy5odG1sJyxcbiAgICAgICAgY29udHJvbGxlcjogJ1Jlc2V0Q3RybCdcbiAgICB9KTtcbn0pO1xuXG5hcHAuY29udHJvbGxlcignUmVzZXRDdHJsJywgZnVuY3Rpb24gKCRzY29wZSwgVXNlckZhY3RvcnksICRzdGF0ZVBhcmFtcywgQXV0aFNlcnZpY2UsICRzdGF0ZSkge1xuXG4gICAgJHNjb3BlLnJlc2V0UGFzcyA9IGZ1bmN0aW9uIChuZXdQYXNzKSB7XG4gICAgICAgIFVzZXJGYWN0b3J5LmVkaXQoJHN0YXRlUGFyYW1zLnVzZXJJZCwgeyduZXdQYXNzJzogZmFsc2UsICdwYXNzd29yZCc6IG5ld1Bhc3N9KVxuICAgICAgICAudGhlbiggZnVuY3Rpb24gKHVzZXIpIHtcbiAgICAgICAgICAgIEF1dGhTZXJ2aWNlLmxvZ2luKHtlbWFpbDogdXNlci5lbWFpbCwgcGFzc3dvcmQ6IG5ld1Bhc3N9KVxuICAgICAgICAgICAgLnRoZW4oZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAkc3RhdGUuZ28oJ2hvbWUnKTtcbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9KVxuICAgIH1cbn0pXG4iLCJhcHAuY29uZmlnKGZ1bmN0aW9uICgkc3RhdGVQcm92aWRlcikge1xuXG4gICAgJHN0YXRlUHJvdmlkZXIuc3RhdGUoJ3NpZ251cCcsIHtcbiAgICAgICAgdXJsOiAnL3NpZ251cCcsXG4gICAgICAgIHRlbXBsYXRlVXJsOiAnanMvc2lnbnVwL3NpZ251cC5odG1sJyxcbiAgICAgICAgY29udHJvbGxlcjogJ1NpZ251cEN0cmwnXG4gICAgfSk7XG5cbn0pO1xuXG5hcHAuY29udHJvbGxlcignU2lnbnVwQ3RybCcsIGZ1bmN0aW9uICgkc2NvcGUsIEF1dGhTZXJ2aWNlLCAkc3RhdGUpIHtcblxuICAgICRzY29wZS5lcnJvciA9IG51bGw7XG5cbiAgICAkc2NvcGUuc2VuZFNpZ251cD0gZnVuY3Rpb24gKHNpZ251cEluZm8pIHtcbiAgICAgICAgJHNjb3BlLmVycm9yID0gbnVsbDtcbiAgICAgICAgQXV0aFNlcnZpY2Uuc2lnbnVwKHNpZ251cEluZm8pXG4gICAgICAgIC50aGVuKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICRzdGF0ZS5nbygnaG9tZScpO1xuICAgICAgICB9KVxuICAgICAgICAuY2F0Y2goZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgJHNjb3BlLmVycm9yID0gJ0VtYWlsIGlzIHRha2VuISc7XG4gICAgICAgIH0pO1xuXG4gICAgfTtcblxufSk7XG4iLCJhcHAuY29uZmlnKGZ1bmN0aW9uKCRzdGF0ZVByb3ZpZGVyKXtcbiAgJHN0YXRlUHJvdmlkZXJcbiAgLnN0YXRlKCd1c2VyJywge1xuICAgIHVybDogJy91c2VyLzp1c2VySWQnLFxuICAgIHRlbXBsYXRlVXJsOiAnL2pzL3VzZXIvdXNlci5odG1sJyxcbiAgICBjb250cm9sbGVyOiBmdW5jdGlvbiAoJHNjb3BlLCBmaW5kVXNlcikge1xuICAgICAgJHNjb3BlLnVzZXIgPSBmaW5kVXNlcjtcbiAgICB9LFxuICAgIHJlc29sdmU6IHtcbiAgICAgIGZpbmRVc2VyOiBmdW5jdGlvbiAoJHN0YXRlUGFyYW1zLCBVc2VyRmFjdG9yeSkge1xuICAgICAgICByZXR1cm4gVXNlckZhY3RvcnkuZ2V0QnlJZCgkc3RhdGVQYXJhbXMudXNlcklkKVxuICAgICAgICAudGhlbihmdW5jdGlvbih1c2VyKXtcbiAgICAgICAgICByZXR1cm4gdXNlcjtcbiAgICAgICAgfSk7XG4gICAgfVxuICAgIH1cbiAgfSk7XG59KTtcbiIsImFwcC5jb25maWcoZnVuY3Rpb24oJHN0YXRlUHJvdmlkZXIpe1xuXHQkc3RhdGVQcm92aWRlci5zdGF0ZSgndXNlcnMnLCB7XG5cdFx0dXJsOiAnL3VzZXJzJyxcblx0XHR0ZW1wbGF0ZVVybDogJy9qcy91c2Vycy91c2Vycy5odG1sJyxcblx0XHRyZXNvbHZlOntcblx0XHRcdHVzZXJzOiBmdW5jdGlvbihVc2VyRmFjdG9yeSl7XG5cdFx0XHRcdHJldHVybiBVc2VyRmFjdG9yeS5nZXRBbGwoKTtcblx0XHRcdH1cblx0XHR9LFxuXHRcdGNvbnRyb2xsZXI6IGZ1bmN0aW9uICgkc2NvcGUsIHVzZXJzLCBTZXNzaW9uLCAkc3RhdGUpIHtcblx0XHRcdCRzY29wZS51c2VycyA9IHVzZXJzO1xuXG4gICAgICAgICAgICAvL1dIWSBOT1QgT04gU0VTU0lPTj8/Pz9cblx0XHRcdC8vIGlmICghU2Vzc2lvbi51c2VyIHx8ICFTZXNzaW9uLnVzZXIuaXNBZG1pbil7XG5cdFx0XHQvLyBcdCRzdGF0ZS5nbygnaG9tZScpO1xuXHRcdFx0Ly8gfVxuXHRcdH1cbn0pO1xufSk7XG4iLCJhcHAuZmFjdG9yeSgnRHdlZXRGYWN0b3J5JywgZnVuY3Rpb24gKCRodHRwKSB7XG4gICAgdmFyIER3ZWV0cyA9IGZ1bmN0aW9uKHByb3BzKSB7XG4gICAgICAgIGFuZ3VsYXIuZXh0ZW5kKHRoaXMsIHByb3BzKTtcbiAgICB9O1xuXG4gICAgRHdlZXRzLmdldEFsbCA9IGZ1bmN0aW9uICgpe1xuICAgICAgICByZXR1cm4gJGh0dHAuZ2V0KCcvYXBpL2RhdGEnKVxuICAgICAgICAudGhlbihmdW5jdGlvbiAocmVzcG9uc2Upe1xuICAgICAgICAgICAgcmV0dXJuIHJlc3BvbnNlLmRhdGE7XG4gICAgICAgIH0pXG5cdH07XG5cbiAgICBEd2VldHMuZ2V0TGF0ZXN0ID0gZnVuY3Rpb24gKCkge1xuICAgICAgICByZXR1cm4gJGh0dHAuZ2V0KCcvYXBpL2RhdGEvbGF0ZXN0JylcbiAgICAgICAgLnRoZW4gKGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgICAgICAgcmV0dXJuIHJlc3BvbnNlLmRhdGE7XG4gICAgICAgIH0pXG4gICAgfTtcblxuICAgIHJldHVybiBEd2VldHM7XG59KVxuIiwiYXBwLmZhY3RvcnkoJ1VzZXJGYWN0b3J5JywgZnVuY3Rpb24oJGh0dHApe1xuXG5cdHZhciBVc2VyID0gZnVuY3Rpb24ocHJvcHMpe1xuXHRcdGFuZ3VsYXIuZXh0ZW5kKHRoaXMsIHByb3BzKTtcblx0fTtcblxuXHRVc2VyLmdldEFsbCA9IGZ1bmN0aW9uICgpe1xuXHRcdHJldHVybiAkaHR0cC5nZXQoJy9hcGkvdXNlcnMnKVxuXHRcdC50aGVuKGZ1bmN0aW9uKHJlc3BvbnNlKXtcblx0XHRcdHJldHVybiByZXNwb25zZS5kYXRhO1xuXHRcdH0pO1xuXHR9O1xuXG5cdFVzZXIuZ2V0QnlJZCA9IGZ1bmN0aW9uIChpZCkge1xuXHRcdHJldHVybiAkaHR0cC5nZXQoJy9hcGkvdXNlcnMvJyArIGlkKVxuXHRcdC50aGVuKGZ1bmN0aW9uKHJlc3BvbnNlKXtcblx0XHRcdHJldHVybiByZXNwb25zZS5kYXRhO1xuXHRcdH0pO1xuXHR9O1xuXG5cdFVzZXIuZWRpdCA9IGZ1bmN0aW9uIChpZCwgcHJvcHMpIHtcblx0XHRyZXR1cm4gJGh0dHAucHV0KCcvYXBpL3VzZXJzLycgKyBpZCwgcHJvcHMpXG5cdFx0LnRoZW4oZnVuY3Rpb24ocmVzcG9uc2Upe1xuXHRcdFx0cmV0dXJuIHJlc3BvbnNlLmRhdGE7XG5cdFx0fSk7XG5cdH07XG5cblx0VXNlci5kZWxldGUgPSBmdW5jdGlvbiAoaWQpIHtcblx0XHRyZXR1cm4gJGh0dHAuZGVsZXRlKCcvYXBpL3VzZXJzLycgKyBpZClcblx0XHQudGhlbihmdW5jdGlvbihyZXNwb25zZSl7XG5cdFx0XHRcdHJldHVybiByZXNwb25zZS5kYXRhO1xuXHRcdH0pO1xuXHR9O1xuXG5cblx0cmV0dXJuIFVzZXI7XG59KTtcbiIsImFwcC5kaXJlY3RpdmUoJ2R3ZWV0TGlzdCcsIGZ1bmN0aW9uKCl7XG4gIHJldHVybiB7XG4gICAgcmVzdHJpY3Q6ICdFJyxcbiAgICB0ZW1wbGF0ZVVybDogJy9qcy9jb21tb24vZGlyZWN0aXZlcy9kd2VldC9kd2VldC1saXN0Lmh0bWwnXG4gIH07XG59KTtcbiIsImFwcC5kaXJlY3RpdmUoJ25hdmJhcicsIGZ1bmN0aW9uICgkcm9vdFNjb3BlLCBBdXRoU2VydmljZSwgQVVUSF9FVkVOVFMsICRzdGF0ZSkge1xuXG4gICAgcmV0dXJuIHtcbiAgICAgICAgcmVzdHJpY3Q6ICdFJyxcbiAgICAgICAgc2NvcGU6IHt9LFxuICAgICAgICB0ZW1wbGF0ZVVybDogJ2pzL2NvbW1vbi9kaXJlY3RpdmVzL25hdmJhci9uYXZiYXIuaHRtbCcsXG4gICAgICAgIGxpbms6IGZ1bmN0aW9uIChzY29wZSkge1xuXG4gICAgICAgICAgICBzY29wZS5pdGVtcyA9IFtcbiAgICAgICAgICAgICAgICB7IGxhYmVsOiAnVXNlcnMnLCBzdGF0ZTogJ3VzZXJzJyB9LFxuICAgICAgICAgICAgICAgIHsgbGFiZWw6ICdEYXRhJywgc3RhdGU6ICdkYXRhJyB9LFxuICAgICAgICAgICAgICAgIHsgbGFiZWw6ICdMYXRlc3QnLCBzdGF0ZTogJ2xhdGVzdCcgfSxcbiAgICAgICAgICAgICAgICB7IGxhYmVsOiAnRG9jdW1lbnRhdGlvbicsIHN0YXRlOiAnZG9jcycgfSxcbiAgICAgICAgICAgIF07XG5cbiAgICAgICAgICAgIHNjb3BlLnVzZXIgPSBudWxsO1xuXG4gICAgICAgICAgICBzY29wZS5pc0xvZ2dlZEluID0gZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgIHJldHVybiBBdXRoU2VydmljZS5pc0F1dGhlbnRpY2F0ZWQoKTtcbiAgICAgICAgICAgIH07XG5cbiAgICAgICAgICAgIHNjb3BlLmxvZ291dCA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICAgICBBdXRoU2VydmljZS5sb2dvdXQoKS50aGVuKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICAgICAgICRzdGF0ZS5nbygnaG9tZScpO1xuICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgfTtcblxuICAgICAgICAgICAgdmFyIHNldFVzZXIgPSBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAgICAgQXV0aFNlcnZpY2UuZ2V0TG9nZ2VkSW5Vc2VyKCkudGhlbihmdW5jdGlvbiAodXNlcikge1xuICAgICAgICAgICAgICAgICAgICBzY29wZS51c2VyID0gdXNlcjtcbiAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgIH07XG5cbiAgICAgICAgICAgIHZhciByZW1vdmVVc2VyID0gZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgIHNjb3BlLnVzZXIgPSBudWxsO1xuICAgICAgICAgICAgfTtcblxuICAgICAgICAgICAgc2V0VXNlcigpO1xuXG4gICAgICAgICAgICAkcm9vdFNjb3BlLiRvbihBVVRIX0VWRU5UUy5sb2dpblN1Y2Nlc3MsIHNldFVzZXIpO1xuICAgICAgICAgICAgJHJvb3RTY29wZS4kb24oQVVUSF9FVkVOVFMuc2lnbnVwU3VjY2Vzcywgc2V0VXNlcik7XG4gICAgICAgICAgICAkcm9vdFNjb3BlLiRvbihBVVRIX0VWRU5UUy5sb2dvdXRTdWNjZXNzLCByZW1vdmVVc2VyKTtcbiAgICAgICAgICAgICRyb290U2NvcGUuJG9uKEFVVEhfRVZFTlRTLnNlc3Npb25UaW1lb3V0LCByZW1vdmVVc2VyKTtcblxuICAgICAgICB9XG5cbiAgICB9O1xuXG59KTtcbiIsImFwcC5kaXJlY3RpdmUoXCJlZGl0QnV0dG9uXCIsIGZ1bmN0aW9uICgpIHtcblx0cmV0dXJuIHtcblx0XHRyZXN0cmljdDogJ0VBJyxcblx0XHR0ZW1wbGF0ZVVybDogJ2pzL2NvbW1vbi9kaXJlY3RpdmVzL2VkaXQtYnV0dG9uL2VkaXQtYnV0dG9uLmh0bWwnLFxuXHR9O1xufSk7XG4iLCJhcHAuZGlyZWN0aXZlKCd1c2VyRGV0YWlsJywgZnVuY3Rpb24oVXNlckZhY3RvcnksICRzdGF0ZVBhcmFtcywgJHN0YXRlLCBTZXNzaW9uKXtcbiAgcmV0dXJuIHtcblx0cmVzdHJpY3Q6ICdFJyxcblx0dGVtcGxhdGVVcmw6ICcvanMvY29tbW9uL2RpcmVjdGl2ZXMvdXNlci91c2VyLWRldGFpbC91c2VyLWRldGFpbC5odG1sJyxcblx0bGluazogZnVuY3Rpb24gKHNjb3BlKXtcblx0XHRzY29wZS5pc0RldGFpbCA9IHRydWU7XG5cdFx0c2NvcGUuaXNBZG1pbiA9IFNlc3Npb24udXNlci5pc0FkbWluO1xuXHRcdHNjb3BlLmVkaXRNb2RlID0gZmFsc2U7XG5cblx0XHRzY29wZS5lbmFibGVFZGl0ID0gZnVuY3Rpb24gKCkge1xuXHRcdFx0c2NvcGUuY2FjaGVkID0gYW5ndWxhci5jb3B5KHNjb3BlLnVzZXIpO1xuXHRcdFx0c2NvcGUuZWRpdE1vZGUgPSB0cnVlO1xuXHRcdH07XG5cdFx0c2NvcGUuY2FuY2VsRWRpdCA9IGZ1bmN0aW9uKCl7XG5cdFx0XHRzY29wZS51c2VyID0gYW5ndWxhci5jb3B5KHNjb3BlLmNhY2hlZCk7XG5cdFx0XHRzY29wZS5lZGl0TW9kZSA9IGZhbHNlO1xuXHRcdH07XG5cdFx0c2NvcGUuc2F2ZVVzZXIgPSBmdW5jdGlvbiAodXNlcikge1xuXHRcdFx0VXNlckZhY3RvcnkuZWRpdCh1c2VyLl9pZCwgdXNlcilcblx0XHRcdC50aGVuKGZ1bmN0aW9uICh1cGRhdGVkVXNlcikge1xuXHRcdFx0XHRzY29wZS51c2VyID0gdXBkYXRlZFVzZXI7XG5cdFx0XHRcdHNjb3BlLmVkaXRNb2RlID0gZmFsc2U7XG5cdFx0XHR9KTtcblx0XHR9O1xuXHRcdHNjb3BlLmRlbGV0ZVVzZXIgPSBmdW5jdGlvbih1c2VyKXtcblx0XHRcdFVzZXJGYWN0b3J5LmRlbGV0ZSh1c2VyKVxuXHRcdFx0LnRoZW4oZnVuY3Rpb24oKXtcblx0XHRcdFx0c2NvcGUuZWRpdE1vZGUgPSBmYWxzZTtcblx0XHRcdFx0JHN0YXRlLmdvKCdob21lJyk7XG5cdFx0XHR9KTtcblx0XHR9O1xuXG4gICAgICAgIHNjb3BlLnJlc2V0UGFzcyA9IGZ1bmN0aW9uKGlkKXtcbiAgICAgICAgICAgIFVzZXJGYWN0b3J5LmVkaXQoaWQsIHsnbmV3UGFzcyc6IHRydWV9KVxuICAgICAgICAgICAgLnRoZW4oZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgIC8vIHNjb3BlLm5ld1Bhc3MgPSB0cnVlO1xuICAgICAgICAgICAgICAgIHNjb3BlLmVkaXRNb2RlID0gZmFsc2U7XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfTtcblx0fSxcblx0c2NvcGU6IHtcblx0XHR1c2VyOiBcIj1cIlxuXHR9XG4gIH07XG59KTtcbiIsImFwcC5kaXJlY3RpdmUoJ3VzZXJMaXN0JywgZnVuY3Rpb24oKXtcbiAgcmV0dXJuIHtcbiAgICByZXN0cmljdDogJ0UnLFxuICAgIHRlbXBsYXRlVXJsOiAnL2pzL2NvbW1vbi9kaXJlY3RpdmVzL3VzZXIvdXNlci1saXN0L3VzZXItbGlzdC5odG1sJ1xuICB9O1xufSk7XG4iXSwic291cmNlUm9vdCI6Ii9zb3VyY2UvIn0=