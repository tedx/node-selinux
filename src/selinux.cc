/* This code is PUBLIC DOMAIN, and is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND. See the accompanying 
 * LICENSE file.
 */

#include <v8.h>
#include <node.h>
#include <pipe_wrap.h>
#include <tcp_wrap.h>
#include <selinux/selinux.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

using namespace node;
using namespace v8;
using ::v8::String;
using ::v8::AccessorInfo;


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
    NODE_SET_PROTOTYPE_METHOD(s_ct, "setsockcreatecon", SetSockCreateCon);

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

  static Handle<Value> GetFd(const Arguments& args) {
    HandleScope scope;

    Local<Object> obj = args[0]->ToObject();
    StreamWrap* wrap = static_cast<StreamWrap*>(obj->GetPointerFromInternalField(0));
    return scope.Close(wrap->GetFD(String::New("fd"), (const v8::AccessorInfo&)NULL));
  }

  static Handle<Value> GetCon(const Arguments& args) {
    HandleScope scope;
    int ret;
    security_context_t context = NULL;

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

  static Handle<Value> SetSockCreateCon(const Arguments& args) {
    HandleScope scope;

    if (args.Length() < 1) {
      ThrowException(Exception::Error(String::New("Must supply a security context.")));
      return Undefined();
    } else if (!args[0]->IsString()) {
      ThrowException(Exception::TypeError(String::New("Param must be string.")));
      return Undefined();
    }

    String::Utf8Value context_str(args[0]->ToString());

    int ret = setsockcreatecon(*context_str);
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
    int fd;
    Persistent<Function> cb;
    security_context_t context;
    char *error_message;
    bool error;
  };

  static Handle<Value> GetPeerCon(const Arguments& args)
  {
    HandleScope scope;

    if (args.Length() < 2) {
      ThrowException(Exception::TypeError(String::New("Wrong number of arguments")));
      return scope.Close(Undefined());
    }

    //    if (!args[0]->IsNumber()) {
    //      ThrowException(Exception::TypeError(String::New("Wrong argument type: arg 1 is not a number")));
    //      return scope.Close(Undefined());
    //    }
    /*    Local<Object> obj = args[0]->ToObject();
    StreamWrap* wrap = static_cast<StreamWrap*>(obj->GetPointerFromInternalField(0));
    */
    REQ_FUN_ARG(1, cb);

    SELinux* hw = ObjectWrap::Unwrap<SELinux>(args.This());

    getpeercon_baton_t *baton = new getpeercon_baton_t();
    baton->fd = (int)(SELinux::GetFd(args))->Int32Value();
    baton->hw = hw;
    baton->error = false;

    hw->Ref();

    uv_work_t *req = new uv_work_t;
    req->data = baton;
    baton->cb = Persistent<Function>::New(cb);
    
    uv_queue_work(uv_default_loop(), req, CallGetPeerCon, AfterGetPeerCon);

    return Undefined();
  }


  static void CallGetPeerCon(uv_work_t *req)
  {
    int ret;
    getpeercon_baton_t *baton = static_cast<getpeercon_baton_t *>(req->data);

    ret = getpeercon(baton->fd, &baton->context);
    if (ret == -1) {
      baton->error_message = strerror(errno);
      baton->error = true;
    }
  }

  static void AfterGetPeerCon(uv_work_t *req, int)
  {
    HandleScope scope;
    getpeercon_baton_t *baton = static_cast<getpeercon_baton_t *>(req->data);
    baton->hw->Unref();

    TryCatch try_catch;

    if (baton->error) {
        const unsigned argc = 1;
        Local<Value> argv[argc] = { Exception::Error(String::New(baton->error_message)) };
	baton->cb->Call(Context::GetCurrent()->Global(), argc, argv);
    }
    else {
        const unsigned argc = 2;
	Local<String> con = String::New((const char *)baton->context);
        Local<Value> argv[argc] = {
            Local<Value>::New(Null()),
	    con
        };
	baton->cb->Call(Context::GetCurrent()->Global(), argc, argv);
	freecon(baton->context);
    }

    if (try_catch.HasCaught()) {
      FatalException(try_catch);
    }

    baton->cb.Dispose();

    delete baton;
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
