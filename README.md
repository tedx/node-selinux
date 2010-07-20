#### Description

node-selinux is an libselinux binding for [node.js](http://nodejs.org/).


#### Requirements

     * [node.js](http://nodejs.org/) -- tested with v0.1.100
     * libselinux

#### Build
To build node-selinux:

	node-waf configure build

#### API

Supported methods
	  * getcon
	  * getpeercon
	  * getfilecon
	  * getcon_raw
	  * setexeccon
	  * setfscreatecon
	  * matchpathcon

#### Example

var sys = require('sys'),
    selinux = require('selinux_node');

var s = new selinux.SELinux();
var con = s.getcon();
sys.puts(con);
