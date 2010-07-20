#include <v8.h>
#include <node.h>
#include <node_events.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <selinux/selinux.h>

using namespace v8;
using namespace node;

struct matchpathcon_request {
  Persistent<Function> cb;
  security_context_t context;
  char path[1];
};

static int AfterMatchPathCon(eio_req *req) {
  ev_unref(EV_DEFAULT_UC);

  struct matchpathcon_request * mreq = (struct matchpathcon_request *)(req->data);

  HandleScope scope;
  Local<Value> argv[2];

  if (req->result == -1) {
    argv[0] = ErrnoException(req->result,
                               "matchpathcon",
                               "matchpathcon failed");
  } else {

    argv[0] = String::New(mreq->context);
  }

  TryCatch try_catch;

  mreq->cb->Call(Context::GetCurrent()->Global(), 1, argv);

  if (try_catch.HasCaught()) {
    FatalException(try_catch);
  }

  if (mreq->context) free(mreq->context);
  mreq->cb.Dispose(); // Dispose of the persistent handle
  free(mreq);

  return 0;
}

static int MatchPathCon(eio_req *req) {
  // Note: this function is executed in the thread pool! CAREFUL
  struct matchpathcon_request * mreq = (struct matchpathcon_request *) req->data;
  security_context_t context = NULL;    /* security context */

  int ret = matchpathcon_init(NULL);
  if (ret == 0) {
    ret = matchpathcon(mreq->path, 0, &context);
    if (ret == 0) {
      mreq->context = strdup(context);
      freecon(context);
    }
    matchpathcon_fini();
  }
  req->result = ret;
  return 0;
}

struct getpeercon_request {
  Persistent<Function> cb;
  security_context_t context;
  int fd;
};

static int AfterGetPeerCon(eio_req *req) {
  ev_unref(EV_DEFAULT_UC);

  struct getpeercon_request * mreq = (struct getpeercon_request *)(req->data);

  HandleScope scope;
  Local<Value> argv[2];

  if (req->result == -1) {
    argv[0] = ErrnoException(req->result,
                               "getpeercon",
                               "getpeercon failed");
  } else {

    argv[0] = String::New(mreq->context);
  }

  TryCatch try_catch;

  mreq->cb->Call(Context::GetCurrent()->Global(), 1, argv);

  if (try_catch.HasCaught()) {
    FatalException(try_catch);
  }

  if (mreq->context) free(mreq->context);
  mreq->cb.Dispose(); // Dispose of the persistent handle
  free(mreq);

  return 0;
}

static int GetPeerCon(eio_req *req) {
  // Note: this function is executed in the thread pool! CAREFUL
  struct getpeercon_request * mreq = (struct getpeercon_request *) req->data;
  security_context_t context = NULL;    /* security context */

  int ret = getpeercon(mreq->fd, &context);
  if (ret == 0) {
      mreq->context = strdup(context);
      freecon(context);
  }
  req->result = ret;
  return 0;
}


class SELinux : public EventEmitter {
 public:
  static void
  Initialize (v8::Handle<v8::Object> target)
  {
    HandleScope scope;

    Local<FunctionTemplate> t = FunctionTemplate::New(New);

    t->Inherit(EventEmitter::constructor_template);
    t->InstanceTemplate()->SetInternalFieldCount(1);

    NODE_SET_PROTOTYPE_METHOD(t, "getcon", SELinuxGetCon);
    NODE_SET_PROTOTYPE_METHOD(t, "getpeercon", SELinuxGetPeerCon);
    NODE_SET_PROTOTYPE_METHOD(t, "getfilecon", SELinuxGetFileCon);
    NODE_SET_PROTOTYPE_METHOD(t, "getcon_raw", SELinuxGetCon);
    NODE_SET_PROTOTYPE_METHOD(t, "setexeccon", SELinuxSetExecCon);
    NODE_SET_PROTOTYPE_METHOD(t, "setfscreatecon", SELinuxSetFSCreateCon);
    NODE_SET_PROTOTYPE_METHOD(t, "matchpathcon", SELinuxMatchPathCon);

    target->Set(String::NewSymbol("SELinux"), t->GetFunction());
  }

  int SELinuxGetCon(char** out, int* out_len) {
    int ret;
    security_context_t context = NULL;    /* security context */

    *out = NULL;
    *out_len = 0;
    ret = getcon(&context);
    if (ret ==  0) {
      *out_len = strlen(context);
      *out = context;
    }
    
    return ret;
  }

  int SELinuxGetPeerCon(int fd, char** out, int* out_len) {
    int ret;
    security_context_t context = NULL;    /* security context */

    *out = NULL;
    *out_len = 0;
    ret = getpeercon(fd, &context);
    if (ret == 0) {
      *out_len = strlen(context);
      *out = context;
    }
    
    return ret;
  }

  int SELinuxGetFileCon(char* path, char** out, int* out_len) {
    int ret = 0;
    security_context_t context = NULL;    /* security context */

    *out = NULL;
    *out_len = 0;
    ret = getfilecon(path, &context);
    if (ret != -1) {
      *out_len = strlen(context);
      *out = context;
    }
    
    return ret;
  }

  int SELinuxGetConRaw(char** out, int* out_len) {
    int ret;
    security_context_t context = NULL;    /* security context */

    *out = NULL;
    *out_len = 0;
    ret = getcon_raw(&context);
    if (ret ==  0) {
      *out_len = strlen(context);
      *out = context;
    }
    
    return ret;
  }

  void SELinuxFreeCon(char* con) {
    freecon(con);
  }

  int SELinuxSetExecCon(char* con) {
    return setexeccon(con);
  }

  int SELinuxSetFSCreateCon(char* con) {
    return setfscreatecon(con);
  }

 protected:

  static Handle<Value>
  New (const Arguments& args)
  {
    HandleScope scope;

    SELinux *selinux = new SELinux();
    selinux->Wrap(args.This());

    return args.This();
  }

  static Handle<Value>
  SELinuxFreeCon(const Arguments& args) {
    SELinux *selinux = ObjectWrap::Unwrap<SELinux>(args.This());

    HandleScope scope;

    if (args.Length() < 1) {
      return ThrowException(Exception::Error(String::New("Must supply a security context.")));
    } else if (!args[0]->IsString()) {
      return ThrowException(Exception::Error(String::New("Param must be string.")));
    }

    String::Utf8Value context_str(args[0]->ToString());

    selinux->SELinuxFreeCon(*context_str);
    return Undefined();
  }

  static Handle<Value>
  SELinuxSetExecCon(const Arguments& args) {
    SELinux *selinux = ObjectWrap::Unwrap<SELinux>(args.This());

    HandleScope scope;

    if (args.Length() < 1) {
      return ThrowException(Exception::Error(String::New("Must supply a security context.")));
    } else if (!args[0]->IsString()) {
      return ThrowException(Exception::Error(String::New("Param must be string.")));
    }

    String::Utf8Value context_str(args[0]->ToString());

    int ret = selinux->SELinuxSetExecCon(*context_str);
    if (ret != 0) return ThrowException(Exception::Error(String::New("setexeccon failed.")));
    return Undefined();
  }

  static Handle<Value>
  SELinuxSetFSCreateCon(const Arguments& args) {
    SELinux *selinux = ObjectWrap::Unwrap<SELinux>(args.This());

    HandleScope scope;

    if (args.Length() < 1) {
      return ThrowException(Exception::Error(String::New("Must supply a security context.")));
    } else if (!args[0]->IsString()) {
      return ThrowException(Exception::Error(String::New("Param must be string.")));
    }

    String::Utf8Value context_str(args[0]->ToString());

    int ret = selinux->SELinuxSetFSCreateCon(*context_str);
    if (ret != 0) return ThrowException(Exception::Error(String::New("setfscreatecon failed.")));
    return Undefined();
  }

  static Handle<Value>
  SELinuxGetCon(const Arguments& args) {
    SELinux *selinux = ObjectWrap::Unwrap<SELinux>(args.This());

    HandleScope scope;

    char* out;
    int out_size;

    int r = selinux->SELinuxGetCon( &out, &out_size);
    if (r < 0)
      return ThrowException(Exception::Error(String::New("getcon failed")));

    if (out_size==0) {
      return String::New("");
    }
    Local<Value> outString = Encode(out, out_size, BINARY);
    freecon(out);
    return scope.Close(outString);
  }

  static Handle<Value>
  SELinuxGetConRaw(const Arguments& args) {
    SELinux *selinux = ObjectWrap::Unwrap<SELinux>(args.This());

    HandleScope scope;

    char* out;
    int out_size;

    int r = selinux->SELinuxGetConRaw( &out, &out_size);
    if (r < 0)
      return ThrowException(Exception::Error(String::New("getcon failed")));

    if (out_size==0) {
      return String::New("");
    }
    Local<Value> outString = Encode(out, out_size, BINARY);
    freecon(out);
    return scope.Close(outString);
  }

  static Handle<Value>
  SELinuxGetPeerCon(const Arguments& args) {

    if (args.Length() < 2) {
      return ThrowException(Exception::Error(String::New("Must supply a file descriptor and a callback function.")));
    } else if (!args[0]->IsInt32()) {
      return ThrowException(Exception::Error(String::New("Param 1 must be an integer.")));
    }
    else if (!args[1]->IsFunction()) {
      return ThrowException(Exception::Error(String::New("Param 2 must be a callback function.")));
    }

    int fd = args[0]->Int32Value();

    Local<Function> cb = Local<Function>::Cast(args[1]);

    struct getpeercon_request *mreq = (struct getpeercon_request *)
      calloc(1, sizeof(struct getpeercon_request));

    if (!mreq) {
      V8::LowMemoryNotification();
      return ThrowException(Exception::Error(
					     String::New("Could not allocate enough memory")));
    }

    mreq->cb = Persistent<Function>::New(cb);
    mreq->fd = fd;

    eio_custom(GetPeerCon, EIO_PRI_DEFAULT, AfterGetPeerCon, mreq);
    
    ev_ref(EV_DEFAULT_UC);
      
    return Undefined();
  }

  static Handle<Value>
  SELinuxGetFileCon(const Arguments& args) {
    SELinux *selinux = ObjectWrap::Unwrap<SELinux>(args.This());

    HandleScope scope;

    if (args.Length() < 1) {
      return ThrowException(Exception::Error(String::New("Must supply a file path.")));
    } else if (!args[0]->IsString()) {
      return ThrowException(Exception::Error(String::New("Param must be string.")));
    }

    String::Utf8Value filepath(args[0]->ToString());

    char* out;
    int out_size;

    int r = selinux->SELinuxGetFileCon(*filepath, &out, &out_size);
    if (r < 0)
      return ThrowException(ErrnoException(errno, "getfilecon"));
    
    if (out_size==0) {
      return String::New("");
    }
    Local<Value> outString = Encode(out, out_size, BINARY);
    freecon(out);
    return scope.Close(outString);
  }

  static Handle<Value>
  SELinuxMatchPathCon(const Arguments& args) {

    if (args.Length() < 2) {
      return ThrowException(Exception::Error(String::New("Must supply a file path and a callback function.")));
    } else if (!args[0]->IsString()) {
      return ThrowException(Exception::Error(String::New("Param 1 must be string.")));
    }
    else if (!args[1]->IsFunction()) {
      return ThrowException(Exception::Error(String::New("Param 2 must be a callback function.")));
    }

    String::Utf8Value filepath(args[0]->ToString());

    Local<Function> cb = Local<Function>::Cast(args[1]);

    struct matchpathcon_request *mreq = (struct matchpathcon_request *)
      calloc(1, sizeof(struct matchpathcon_request) + filepath.length());

    if (!mreq) {
      V8::LowMemoryNotification();
      return ThrowException(Exception::Error(
					     String::New("Could not allocate enough memory")));
    }

    mreq->cb = Persistent<Function>::New(cb);
    strcpy(mreq->path, *filepath);

    eio_custom(MatchPathCon, EIO_PRI_DEFAULT, AfterMatchPathCon, mreq);
    
    ev_ref(EV_DEFAULT_UC);
      
    return Undefined();

  }


  SELinux () : EventEmitter () 
  {
  }

  ~SELinux ()
  {
  }

 private:

};


extern "C" void
init (Handle<Object> target) 
{
  HandleScope scope;
  SELinux::Initialize(target);
}
