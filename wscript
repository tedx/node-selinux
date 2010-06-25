import Options
from os import unlink, symlink, popen
from os.path import exists 

srcdir = "."
blddir = "build"
VERSION = "0.0.1"

def set_options(opt):
  opt.tool_options("compiler_cxx")
  opt.tool_options("compiler_cc")

def configure(conf):
  conf.check_tool("compiler_cxx")
  conf.check_tool("compiler_cc")
  conf.check_tool("node_addon")

  if not conf.check(lib='selinux', libpath=['/usr/lib64'], uselib_store='LIBSELINUX'):
    conf.fatal("Cannot find selinux libraries.")

def build(bld):
  selinuxnode = bld.new_task_gen("cxx", "shlib", "node_addon")
  selinuxnode.target = "selinux_node"
  selinuxnode.source = """
    selinux_node.cc
  """
  selinuxnode.includes = """
    /usr/includes/selinux/
  """
  selinuxnode.uselib = 'LIBSELINUX'

def shutdown():
  # HACK to get selinux.node out of build directory.
  # better way to do this?
  if Options.commands['clean']:
    if exists('selinux_node.node'): unlink('selinux_node.node')
  else:
    if exists('build/default/selinux_node.node') and not exists('selinux_node.node'):
      symlink('build/default/selinux_node.node', 'selinux_node.node')
