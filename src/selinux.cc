/* This code is PUBLIC DOMAIN, and is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND. See the accompanying 
 * LICENSE file.
 */

#include <v8.h>
#include <node.h>
#include <selinux/selinux.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

using namespace node;
using namespace v8;

#define REQ_FUN_ARG(I, VAR)                                             \
  if (args.Length() <= (I) || !args[I]->IsFunction())                   \
    return ThrowException(Exception::TypeError(                         \
                  String::New("Argument " #I " must be a function")));  \
  Local<Function> VAR = Local<Function>::Cast(args[I]);

class SELinux: ObjectWrap
{
public:

  static Persistent<FunctionTemplate> s_ct;
  static void Init(Handle<Object> target)
  {
    HandleScope scope;

    Local<FunctionTemplate> t = FunctionTemplate::New(New);

    s_ct = Persistent<FunctionTemplate>::New(t);
    s_ct->InstanceTemplate()->SetInternalFieldCount(1);
    s_ct->SetClassName(String::NewSymbol("SELinux"));

    NODE_SET_PROTOTYPE_METHOD(s_ct, "getpeercon", GetPeerCon);
    NODE_SET_PROTOTYPE_METHOD(s_ct, "getcon", GetCon);
    NODE_SET_PROTOTYPE_METHOD(s_ct, "getcon_raw", GetConRaw);
    NODE_SET_PROTOTYPE_METHOD(s_ct, "getfilecon", GetFileCon);
    NODE_SET_PROTOTYPE_METHOD(s_ct, "setexeccon", SetExecCon);
    NODE_SET_PROTOTYPE_METHOD(s_ct, "setfscreatecon", SetFSCreateCon);

    target->Set(String::NewSymbol("SELinux"),
                s_ct->GetFunction());
  }

  SELinux()
  {
  }

  ~SELinux()
  {
  }

  static Handle<Value> New(const Arguments& args)
  {
    HandleScope scope;
    SELinux* hw = new SELinux();
    hw->Wrap(args.This());
    return args.This();
  }

  static Handle<Value> GetCon(const Arguments& args) {
    HandleScope scope;
    int ret;
    security_context_t context = NULL;    /* security context */

    ret = getcon(&context);
    if (ret ==  0) {
      v8::Local<v8::String> con = String::New((const char *)context);
      freecon(context);
      return scope.Close(con);
    }
    ThrowException(Exception::Error(String::New("Error getting selinux context")));
    return scope.Close(Undefined());
  }

  static Handle<Value> GetConRaw(const Arguments& args) {
    HandleScope scope;
    int ret;
    security_context_t context = NULL;    /* security context */
    
    ret = getcon_raw(&context);
    if (ret ==  0) {
      v8::Local<v8::String> con = String::New((const char *)context);
      freecon(context);
      return scope.Close(con);
    }
    ThrowException(Exception::Error(String::New("Error getting selinux context")));
    return scope.Close(Undefined());
  }

  static Handle<Value> GetFileCon(const Arguments& args) {
    HandleScope scope;
    int ret;
    security_context_t context = NULL;    /* security context */

    if (args.Length() < 1) {
      ThrowException(Exception::TypeError(String::New("Wrong number of arguments")));
      return scope.Close(Undefined());
    }

    if (!args[0]->IsString()) {
      ThrowException(Exception::TypeError(String::New("Wrong argument type")));
      return scope.Close(Undefined());
    }
    // get the pathname
    v8::String::Utf8Value pathname(args[0]->ToString());
    ret = getfilecon(*pathname, &context);
    if (ret != -1) {
      v8::Local<v8::String> con = String::New((const char *)context);
      freecon(context);
      return scope.Close(con);
    }

    ThrowException(Exception::Error(String::New(strerror(errno))));
    return scope.Close(Undefined());
  }

  static Handle<Value> SetFSCreateCon(const Arguments& args) {
    HandleScope scope;

    if (args.Length() < 1) {
      ThrowException(Exception::Error(String::New("Must supply a security context.")));
      return Undefined();
    } else if (!args[0]->IsString()) {
      ThrowException(Exception::TypeError(String::New("Param must be string.")));
      return Undefined();
    }

    String::Utf8Value context_str(args[0]->ToString());

    int ret = setfscreatecon(*context_str);
    if (ret != 0) {
      ThrowException(Exception::Error(String::New("setfscreatecon failed.")));
    }
    return Undefined();
  }

  static Handle<Value> SetExecCon(const Arguments& args) {
    HandleScope scope;
    int ret;
    
    if (args.Length() < 1) {
      ThrowException(Exception::TypeError(String::New("Wrong number of arguments")));
      return scope.Close(Undefined());
    }

    if (!args[0]->IsString()) {
      ThrowException(Exception::TypeError(String::New("Wrong argument type")));
      return scope.Close(Undefined());
    }
    // get the pathname
    v8::String::Utf8Value con(args[0]->ToString());
    ret = setexeccon(*con);
    Local<Number> num = Number::New(ret);
    return scope.Close(num);
    
    ThrowException(Exception::Error(String::New(strerror(errno))));
    return scope.Close(Undefined());
  }

  struct getpeercon_baton_t {
    SELinux *hw;
    int increment_by;
    int fd;
    Persistent<Function> cb;
    v8::Local<v8::String> con;
  };

  static Handle<Value> GetPeerCon(const Arguments& args)
  {
    HandleScope scope;

    if (args.Length() < 2) {
      ThrowException(Exception::TypeError(String::New("Wrong number of arguments")));
      return scope.Close(Undefined());
    }

    if (!args[0]->IsNumber()) {
      ThrowException(Exception::TypeError(String::New("Wrong argument type: arg 1 is not a number")));
      return scope.Close(Undefined());
    }

    REQ_FUN_ARG(1, cb);

    SELinux* hw = ObjectWrap::Unwrap<SELinux>(args.This());

    getpeercon_baton_t *baton = new getpeercon_baton_t();
    baton->fd = args[0]->IntegerValue();
    baton->hw = hw;
    baton->increment_by = 2;
    baton->cb = Persistent<Function>::New(cb);
    
    hw->Ref();

    eio_custom(EIO_GetPeerCon, EIO_PRI_DEFAULT, EIO_AfterGetPeerCon, baton);
    ev_ref(EV_DEFAULT_UC);

    return Undefined();
  }


  static int EIO_GetPeerCon(eio_req *req)
  {
    int ret;
    security_context_t context = NULL;    /* security context */
    getpeercon_baton_t *baton = static_cast<getpeercon_baton_t *>(req->data);

    ret = getpeercon(baton->fd, &context);
    if (ret == 0) {
      v8::Local<v8::String> con = String::New((const char *)context);
      freecon(context);
      baton->con =  con;
      return 0;
    }

    ThrowException(Exception::Error(String::New("Error getting peer selinux context")));

    return 0;
  }

  static int EIO_AfterGetPeerCon(eio_req *req)
  {
    HandleScope scope;
    getpeercon_baton_t *baton = static_cast<getpeercon_baton_t *>(req->data);
    ev_unref(EV_DEFAULT_UC);
    baton->hw->Unref();

    Local<Value> argv[1];

    argv[0] = baton->con;

    TryCatch try_catch;

    baton->cb->Call(Context::GetCurrent()->Global(), 1, argv);

    if (try_catch.HasCaught()) {
      FatalException(try_catch);
    }

    baton->cb.Dispose();

    delete baton;
    return 0;
  }

};

Persistent<FunctionTemplate> SELinux::s_ct;

extern "C" {
  static void init (Handle<Object> target)
  {
    SELinux::Init(target);
  }

  NODE_MODULE(selinux, init);
}
