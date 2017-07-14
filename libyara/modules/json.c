#include <jansson.h>
#include <stdio.h>
#include <yara/modules.h>

#define MODULE_NAME json


define_function(has_key) {
  json_t* json = (json_t*)module()->data;
  if (json == NULL) {
  return_integer(UNDEFINED);
  }

  char* key = string_argument(1);
  json_t* json_value = json_object_get(json, key);

  if (json_value == NULL) {
    return_integer(0);
  }
  return_integer(1);
}

begin_declarations;

  declare_function("has_key", "s", "i", has_key);
  declare_string_dictionary("keys");

end_declarations;


int module_initialize(YR_MODULE* module) {
  return ERROR_SUCCESS;
}


int module_finalize(YR_MODULE* module) {
  return ERROR_SUCCESS;
}


int module_load(YR_SCAN_CONTEXT* context, YR_OBJECT* module_object, void* module_data, size_t module_data_size) {
  YR_MEMORY_BLOCK* block = first_memory_block(context);
  uint8_t* block_data = block->fetch_data(block);

  json_error_t json_error;
  json_t* json = json_loads((const char*) block_data, 0, &json_error);
  module_object->data = json;

  if (json) {
  const char* key;
  json_t* value;
  
  json_object_foreach(json, key, value) {
    char* json_val = json_dumps(value, JSON_ENCODE_ANY);
    char* to_free = json_val;

    // remove leading and trailing " from string
    int len = strlen(json_val);
    if ((len > 1) && (json_val[0] == '"') && (json_val[len - 1] == '"')) {
    json_val[len - 1] = '\0';
    json_val += 1;
    }

    set_string(json_val, module_object, "keys[%s]", key);
    free(to_free);
  }
  }

  return ERROR_SUCCESS;
}


int module_unload(YR_OBJECT* module_object) {
  if (module_object->data) {
  json_decref((json_t*)module_object->data);
  }
  
  return ERROR_SUCCESS;
}