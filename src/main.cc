//#include <cmath>
#include <node.h>
#include <node_buffer.h>
#include <v8.h>
#include <stdint.h>
#include <string>
#include <algorithm>
#include "currency_core/currency_basic.h"
#include "currency_core/currency_format_utils.h"
#include "currency_protocol/blobdatatype.h"
#include "crypto/crypto.h"
#include "crypto/hash.h"
#include "common/base58.h"
#include "serialization/binary_utils.h"
#include "currency_core/basic_pow_helpers.h"
#include <nan.h>

#define THROW_ERROR_EXCEPTION(x) Nan::ThrowError(x)

void callback(char* data, void* hint) {
  free(data);
}

using namespace node;
using namespace v8;
using namespace currency;

blobdata uint64be_to_blob(uint64_t num) {
    blobdata res = "        ";
    res[0] = num >> 56 & 0xff;
    res[1] = num >> 48 & 0xff;
    res[2] = num >> 40 & 0xff;
    res[3] = num >> 32 & 0xff;
    res[4] = num >> 24 & 0xff;
    res[5] = num >> 16 & 0xff;
    res[6] = num >> 8  & 0xff;
    res[7] = num       & 0xff;
    return res;
}

const size_t MM_NONCE_SIZE = 1 + 2 + sizeof(crypto::hash);

NAN_METHOD(get_merged_mining_nonce_size) {
    Local<Integer> returnValue = Nan::New(static_cast<uint32_t>(MM_NONCE_SIZE));
    info.GetReturnValue().Set(returnValue);
}

NAN_METHOD(convert_blob) {

    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    //Local<Object> target = info[0]->ToObject();
    v8::Isolate *isolate = v8::Isolate::GetCurrent();
    Local<Object> target = info[0]->ToObject(isolate->GetCurrentContext()).ToLocalChecked();

    if (!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    blobdata input = std::string(Buffer::Data(target), Buffer::Length(target));
    blobdata output = "";

    //convert
    block b = AUTO_VAL_INIT(b);
    if (!parse_and_validate_block_from_blob(input, b))
        return THROW_ERROR_EXCEPTION("Failed to parse block");

    output = get_block_hashing_blob(b);

    v8::Local<v8::Value> returnValue = Nan::CopyBuffer((char*)output.data(), output.size()).ToLocalChecked();
    info.GetReturnValue().Set(
        returnValue
    );
}


void address_decode(const Nan::FunctionCallbackInfo<v8::Value>& info) {

    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    //Local<Object> target = info[0]->ToObject();
    v8::Isolate *isolate = v8::Isolate::GetCurrent();
    Local<Object> target = info[0]->ToObject(isolate->GetCurrentContext()).ToLocalChecked();

    if (!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    blobdata input = std::string(Buffer::Data(target), Buffer::Length(target));

    blobdata data;
    uint64_t prefix;
    if (!tools::base58::decode_addr(input, prefix, data))
    {
        info.GetReturnValue().Set(Nan::Undefined());
    }
    //    info.GetReturnValue().Set(Nan::Undefined());


    account_public_address adr;
    if (!::serialization::parse_binary(data, adr) || !crypto::check_key(adr.spend_public_key) || !crypto::check_key(adr.view_public_key))
    {
        if(data.length())
        {
            data = uint64be_to_blob(prefix) + data;
        }
        else
        {
            info.GetReturnValue().Set(Nan::Undefined());
        }

        v8::Local<v8::Value> returnValue = Nan::CopyBuffer((char*)data.data(), data.size()).ToLocalChecked();

        info.GetReturnValue().Set( returnValue);

    }
    else
    {
        info.GetReturnValue().Set(Nan::New(static_cast<uint32_t>(prefix)));
    }
}

/*
Arguments:
1: block_header_hash - 32-byte buffer
2: nonce             - 8-byte buffer
2: height            - 8-byte buffer
*/
void get_pow_hash(const Nan::FunctionCallbackInfo<v8::Value>& info) {

    if (info.Length() < 3)
        return THROW_ERROR_EXCEPTION("You must provide 3 arguments.");

    //Local<Object> block_header_hash = args[0]->ToObject();
    v8::Isolate *isolate = v8::Isolate::GetCurrent();
    Local<Object> block_header_hash = info[0]->ToObject(isolate->GetCurrentContext()).ToLocalChecked();
    
    //Local<Object> nonce = args[1]->ToObject();
    Local<Object> nonce = info[1]->ToObject(isolate->GetCurrentContext()).ToLocalChecked();
    
    //Local<Object> height = args[2]->ToObject();
    Local<Object> height = info[2]->ToObject(isolate->GetCurrentContext()).ToLocalChecked();

    if(!Buffer::HasInstance(block_header_hash))
        return THROW_ERROR_EXCEPTION("Argument 1 should be a buffer object.");

    if(!Buffer::HasInstance(nonce))
        return THROW_ERROR_EXCEPTION("Argument 2 should be a buffer object.");

    if (!Buffer::HasInstance(height))
      return THROW_ERROR_EXCEPTION("Argument 3 should be a buffer object.");

    uint32_t block_header_hash_len = Buffer::Length(block_header_hash);
    uint64_t nonce_len = Buffer::Length(nonce);
    uint64_t height_len = Buffer::Length(height);

    if(block_header_hash_len != 32)
      return THROW_ERROR_EXCEPTION("Argument 1 should be a buffer object of 32 bytes long.");

    if (nonce_len != 8)
      return THROW_ERROR_EXCEPTION("Argument 2 should be a buffer object of 8 bytes long.");

    if (height_len != 8)
      return THROW_ERROR_EXCEPTION("Argument 3 should be a buffer object of 8 bytes long.");

    crypto::hash block_header_hash_val = *(crypto::hash*)Buffer::Data(block_header_hash);
    uint64_t nonce_val = *(uint64_t*)Buffer::Data(nonce);
    uint64_t height_val = *(uint64_t*)Buffer::Data(height);


    crypto::hash h = currency::get_block_longhash(height_val, block_header_hash_val, nonce_val);

    //SET_BUFFER_RETURN((const char*)&h, 32);
    char *cstr = reinterpret_cast<char*>(&h);
    v8::Local<v8::Value> returnValue = Nan::CopyBuffer(cstr, 32).ToLocalChecked();
    info.GetReturnValue().Set(returnValue);
}

/*
Arguments:
1: block_template_buffer - n-byte buffer
2: extra_data            - n-byte buffer(job identification)
*/
void get_hash_from_block_template_with_extra(const Nan::FunctionCallbackInfo<v8::Value>& info) {

  if (info.Length() < 2)
    return THROW_ERROR_EXCEPTION("You must provide 2 arguments.");

  //Local<Object> block_template_buffer = args[0]->ToObject();
  v8::Isolate *isolate = v8::Isolate::GetCurrent();
  Local<Object> block_template_buffer = info[0]->ToObject(isolate->GetCurrentContext()).ToLocalChecked();
  
  //Local<Object> extra_data = args[1]->ToObject();
  Local<Object> extra_data = info[1]->ToObject(isolate->GetCurrentContext()).ToLocalChecked();


  if (!Buffer::HasInstance(block_template_buffer))
    return THROW_ERROR_EXCEPTION("Argument 1 should be a buffer object.");

  if (!Buffer::HasInstance(extra_data))
    return THROW_ERROR_EXCEPTION("Argument 2 should be a buffer object.");

  uint64_t block_template_buffer_len = Buffer::Length(block_template_buffer);
  uint64_t extra_data_len = Buffer::Length(extra_data);

  char* block_template_buffer_ptr = Buffer::Data(block_template_buffer);
  std::string blob(block_template_buffer_ptr, block_template_buffer_len);

  char* extra_data_ptr = Buffer::Data(extra_data);
  std::string extra(extra_data_ptr, extra_data_len);

  currency::block b = AUTO_VAL_INIT(b);
  bool res = currency::parse_and_validate_block_from_blob(blob, b);
  if (!res)
    return THROW_ERROR_EXCEPTION("Unable to parse block");

  if (extra.size())
    b.miner_tx.extra.push_back(extra);

  crypto::hash h = currency::get_block_header_mining_hash(b);

  //SET_BUFFER_RETURN((const char*)&h, 32);
  char *cstr = reinterpret_cast<char*>(&h);
  v8::Local<v8::Value> returnValue = Nan::CopyBuffer(cstr, 32).ToLocalChecked();
  info.GetReturnValue().Set(returnValue);
}

/*
Arguments:
1: block_template_buffer - n-byte buffer
2: extra_data            - n-byte buffer(job identification)
3: nonce                 - 8-byte buffer - nonce
*/
void get_blob_from_block_template(const Nan::FunctionCallbackInfo<v8::Value>& info) {

  if (info.Length() < 3)
    return THROW_ERROR_EXCEPTION("You must provide 3 arguments.");

  //Local<Object> block_template_buffer = args[0]->ToObject();
  v8::Isolate *isolate = v8::Isolate::GetCurrent();
  Local<Object> block_template_buffer = info[0]->ToObject(isolate->GetCurrentContext()).ToLocalChecked();
    
  //Local<Object> extra_data = args[1]->ToObject();
  Local<Object> extra_data = info[1]->ToObject(isolate->GetCurrentContext()).ToLocalChecked();
  
  //Local<Object> nonce = args[2]->ToObject();
  Local<Object> nonce = info[2]->ToObject(isolate->GetCurrentContext()).ToLocalChecked();


  if (!Buffer::HasInstance(block_template_buffer))
    return THROW_ERROR_EXCEPTION("Argument 1 should be a buffer object.");

  if (!Buffer::HasInstance(extra_data))
    return THROW_ERROR_EXCEPTION("Argument 2 should be a buffer object.");

  if (!Buffer::HasInstance(nonce))
    return THROW_ERROR_EXCEPTION("Argument 3 should be a buffer object.");

  uint64_t block_template_buffer_len = Buffer::Length(block_template_buffer);
  uint64_t extra_data_len = Buffer::Length(extra_data);
  uint64_t nonce_len = Buffer::Length(nonce);

  if (nonce_len != 8)
    return THROW_ERROR_EXCEPTION("Argument 3 should be a buffer object of 8 bytes long.");

  char* block_template_buffer_ptr = Buffer::Data(block_template_buffer);
  std::string blob(block_template_buffer_ptr, block_template_buffer_len);

  char* extra_data_ptr = Buffer::Data(extra_data);
  std::string extra(extra_data_ptr, extra_data_len);

  uint64_t nonce_val = *(uint64_t* )Buffer::Data(nonce);

  currency::block b = AUTO_VAL_INIT(b);
  bool res = currency::parse_and_validate_block_from_blob(blob, b);
  if (!res)
    return THROW_ERROR_EXCEPTION("Unable to parse block");

  if (extra.size())
    b.miner_tx.extra.push_back(extra);

  b.nonce = nonce_val;

  std::string result_blob = currency::block_to_blob(b);

  crypto::hash h = currency::get_block_hash(b);

  //SET_BUFFER_RETURN(result_blob.data(), result_blob.size());
  v8::Local<v8::Value> returnValue = Nan::CopyBuffer((char*)result_blob.data(), result_blob.size()).ToLocalChecked();
  info.GetReturnValue().Set(returnValue);
}


void get_id_hash(const Nan::FunctionCallbackInfo<v8::Value>& info) {

  if (info.Length() < 1)
    return THROW_ERROR_EXCEPTION("You must provide 2 arguments.");
    
  v8::Isolate *isolate = v8::Isolate::GetCurrent();
  Local<Object> block_buffer = info[0]->ToObject(isolate->GetCurrentContext()).ToLocalChecked();

  if (!Buffer::HasInstance(block_buffer))
    return THROW_ERROR_EXCEPTION("Argument 1 should be a buffer object.");

  uint64_t block_buffer_len = Buffer::Length(block_buffer);

  char* block_buffer_ptr = Buffer::Data(block_buffer);
  std::string blob(block_buffer_ptr, block_buffer_len);

  currency::block b = AUTO_VAL_INIT(b);
  bool res = currency::parse_and_validate_block_from_blob(blob, b);
  if (!res)
    return THROW_ERROR_EXCEPTION("Unable to parse block");

  crypto::hash h = currency::get_block_hash(b);

  //SET_BUFFER_RETURN((const char*)&h, 32);
  char *cstr = reinterpret_cast<char*>(&h);
  v8::Local<v8::Value> returnValue = Nan::CopyBuffer(cstr, 32).ToLocalChecked();
  info.GetReturnValue().Set(returnValue);
}



void is_address_valid(const Nan::FunctionCallbackInfo<v8::Value>& info)
{

    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");
    
    v8::Isolate *isolate = v8::Isolate::GetCurrent();
    Local<Object> target = info[0]->ToObject(isolate->GetCurrentContext()).ToLocalChecked();
    
    if (!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    blobdata input = std::string(Buffer::Data(target), Buffer::Length(target));

    account_public_address adr;
    bool r = get_account_address_from_str(adr, input);
    if(!r)
    {
       info.GetReturnValue().Set(Nan::Undefined());
    }
    else
    {
       info.GetReturnValue().Set(Nan::True());
    }
}



NAN_MODULE_INIT(init) {
    Nan::Set(target, Nan::New("convert_blob").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(convert_blob)).ToLocalChecked());
    Nan::Set(target, Nan::New("address_decode").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(address_decode)).ToLocalChecked());
    Nan::Set(target, Nan::New("get_pow_hash").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(get_pow_hash)).ToLocalChecked());
    Nan::Set(target, Nan::New("get_hash_from_block_template_with_extra").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(get_hash_from_block_template_with_extra)).ToLocalChecked());
    Nan::Set(target, Nan::New("get_blob_from_block_template").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(get_blob_from_block_template)).ToLocalChecked());
    Nan::Set(target, Nan::New("get_id_hash").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(get_id_hash)).ToLocalChecked());
    Nan::Set(target, Nan::New("is_address_valid").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(is_address_valid)).ToLocalChecked());
    Nan::Set(target, Nan::New("get_merged_mining_nonce_size").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(get_merged_mining_nonce_size)).ToLocalChecked());

}

NODE_MODULE(cryptonote, init)