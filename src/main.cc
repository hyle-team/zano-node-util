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
#include "crypto/wild_keccak.h"
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

void construct_block_blob(const Nan::FunctionCallbackInfo<v8::Value>& info) {

    if (info.Length() < 2)
        return THROW_ERROR_EXCEPTION("You must provide two arguments.");

    Local<Object> block_template_buf = info[0]->ToObject();
    Local<Object> nonce_buf = info[1]->ToObject();

    if (!Buffer::HasInstance(block_template_buf) || !Buffer::HasInstance(nonce_buf))
        return THROW_ERROR_EXCEPTION("Both arguments should be buffer objects.");

    if (Buffer::Length(nonce_buf) != 4)
        return THROW_ERROR_EXCEPTION("Nonce buffer has invalid size.");

    uint32_t nonce = *reinterpret_cast<uint32_t*>(Buffer::Data(nonce_buf));

    blobdata block_template_blob = std::string(Buffer::Data(block_template_buf), Buffer::Length(block_template_buf));
    blobdata output = "";

    block b = AUTO_VAL_INIT(b);
    if (!parse_and_validate_block_from_blob(block_template_blob, b))
        return THROW_ERROR_EXCEPTION("Failed to parse block");
    b.nonce = nonce;
    if (!block_to_blob(b, output))
        return THROW_ERROR_EXCEPTION("Failed to convert block to blob");

    v8::Local<v8::Value> returnValue = Nan::CopyBuffer((char*)output.data(), output.size()).ToLocalChecked();
    info.GetReturnValue().Set(
        returnValue
    );
}

NAN_METHOD(convert_blob) {

    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();

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

    Local<Object> target = info[0]->ToObject();

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
    if (!::serialization::parse_binary(data, adr) || !crypto::check_key(adr.m_spend_public_key) || !crypto::check_key(adr.m_view_public_key))
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

#define SET_BUFFER_RETURN(x, len) \
    args.GetReturnValue().Set(Buffer::Copy(isolate, x, len).ToLocalChecked());

void get_pow_hash(const Nan::FunctionCallbackInfo<v8::Value>& args) {

    if (args.Length() < 2)
        return THROW_ERROR_EXCEPTION("You must provide at least two arguments.");

    Local<Object> target = args[0]->ToObject();
    Local<Object> target_spad = args[1]->ToObject();
    uint32_t height = 1;

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument 1 should be a buffer object.");

    if(!Buffer::HasInstance(target_spad))
        return THROW_ERROR_EXCEPTION("Argument 2 should be a buffer object.");

    if(args.Length() >= 3) {
        if(args[2]->IsUint32())
            height = args[2]->Uint32Value();
        else
            return THROW_ERROR_EXCEPTION("Argument 3 should be an unsigned integer.");
    }

    char * input = Buffer::Data(target);
    char * scratchpad = Buffer::Data(target_spad);
    
    crypto::hash h = AUTO_VAL_INIT(h);
    char* output = reinterpret_cast<char* >(&h);


    uint32_t input_len = Buffer::Length(target);
    uint64_t spad_len = Buffer::Length(target_spad);

    std::string hashing_blob(input, input_len);

    crypto::get_wild_keccak2(hashing_blob, h, (const uint64_t*)&scratchpad[0], spad_len/8);

    v8::Isolate* isolate = args.GetIsolate();

    SET_BUFFER_RETURN(output, 32);
}


void get_id_hash(const Nan::FunctionCallbackInfo<v8::Value>& args) {

    if (args.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument 1 should be a buffer object.");


    char * input = Buffer::Data(target);
    
    crypto::hash h = AUTO_VAL_INIT(h);
    char* output = reinterpret_cast<char* >(&h);

    uint32_t input_len = Buffer::Length(target);

    crypto::cn_fast_hash(input, input_len, h);

    v8::Isolate* isolate = args.GetIsolate();

    SET_BUFFER_RETURN(output, 32);
}

NAN_METHOD(generate_scratchpad) {
    if (info.Length() != 2)
        return THROW_ERROR_EXCEPTION("You must provide two arguments.");

    Local<Object> seed = info[0]->ToObject();

    if(!Buffer::HasInstance(seed))
        return THROW_ERROR_EXCEPTION("Argument 1 should be a buffer object.");

    char * s = Buffer::Data(seed);

    if(!info[1]->IsInt32())
        return THROW_ERROR_EXCEPTION("Argument 2 should be an int32");
    int height = info[1]->IntegerValue();

    uint64_t result_len = get_scratchpad_size_for_height(height);

    char *output = (char *) malloc((size_t) result_len);

    crypto::hash sh = *(crypto::hash*) s;
    std::vector<crypto::hash> result;
    crypto::generate_scratchpad(sh, result, result_len);

    v8::Local<v8::Value> returnValue = Nan::CopyBuffer((char *) result.data(), result_len).ToLocalChecked();
    info.GetReturnValue().Set(
        returnValue
    );

    free(output);
}

NAN_MODULE_INIT(init) {
    Nan::Set(target, Nan::New("construct_block_blob").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(construct_block_blob)).ToLocalChecked());
    Nan::Set(target, Nan::New("convert_blob").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(convert_blob)).ToLocalChecked());
    Nan::Set(target, Nan::New("address_decode").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(address_decode)).ToLocalChecked());
    Nan::Set(target, Nan::New("get_pow_hash").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(get_pow_hash)).ToLocalChecked());
    Nan::Set(target, Nan::New("get_id_hash").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(get_id_hash)).ToLocalChecked());
    Nan::Set(target, Nan::New("generate_scratchpad").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(generate_scratchpad)).ToLocalChecked());
}

NODE_MODULE(cryptonote, init)
