// Written in 2014-2016 by Dmitry Chestnykh and Devi Mandiri.
// Public domain.
// modified by parabirb so i can use it in discord
(function (root, f) {
    'use strict';
    root.nacl.util = f();
}(window, function () {
    'use strict';

    var util = {};

    function validateBase64(s) {
        if (!(/^(?:[A-Za-z0-9+\/]{2}[A-Za-z0-9+\/]{2})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?$/.test(s))) {
            throw new TypeError('invalid encoding');
        }
    }

    util.decodeUTF8 = function (s) {
        if (typeof s !== 'string') throw new TypeError('expected string');
        var i, d = unescape(encodeURIComponent(s)), b = new Uint8Array(d.length);
        for (i = 0; i < d.length; i++) b[i] = d.charCodeAt(i);
        return b;
    };

    util.encodeUTF8 = function (arr) {
        var i, s = [];
        for (i = 0; i < arr.length; i++) s.push(String.fromCharCode(arr[i]));
        return decodeURIComponent(escape(s.join('')));
    };

    util.encodeBase64 = function (arr) { // v6 and later
        return Buffer.from(arr).toString('base64');
    };

    util.decodeBase64 = function (s) {
        validateBase64(s);
        return new Uint8Array(Array.prototype.slice.call(Buffer.from(s, 'base64'), 0));
    };


    return util;

}));
