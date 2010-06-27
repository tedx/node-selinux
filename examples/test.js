var sys = require('sys'),
    selinux = require('../selinux_node');

var s = new selinux.SELinux();
var con = s.getcon();
sys.puts(con);
sys.puts(s.getfilecon("./test.js"));
