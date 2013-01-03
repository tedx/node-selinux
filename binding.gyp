{
  "targets": [
    {
      "target_name": "selinux",
      "sources": [ "src/selinux.cc" ],
      'link_settings': {
            'libraries': ['-lselinux']
       }
    }
  ]
}
