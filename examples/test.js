var selinux = require('./build/Release/selinux');

selx = new selinux.SELinux();
console.log('context: ' + selx.getcon());
console.log('raw context: ' + selx.getcon_raw());
console.log('/etc/selinux/config context: ' + selx.getfilecon('/etc/selinux/config'));

