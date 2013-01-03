#### Description

node-selinux is an libselinux binding for [node.js](http://nodejs.org/).


#### Requirements

     * [node.js](http://nodejs.org/) -- tested with v0.8.16
     * libselinux

#### Build
To build node-selinux:

	node-gyp configure build

#### API

Supported methods
	  * getcon
	  * getpeercon
	  * getfilecon
	  * getcon_raw
	  * setexeccon
	  * setfscreatecon

#### Example

var sys = require('sys');
var selinux = require('selinux');

var s = new selinux.SELinux();
var con = s.getcon();
sys.puts(con);
