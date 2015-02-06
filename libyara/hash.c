/*
Copyright (c) 2013. The YARA Authors. All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <stdint.h>
#include <string.h>

#include <yara/hash.h>
#include <yara/mem.h>
#include <yara/error.h>

#define ROTATE_INT32(x, shift) \
    ((x << (shift % 32)) | (x >> (32 - (shift % 32))))


uint32_t byte_to_int32[]  =
{
  0xC3113E7F,0x4C353C5F,0x7423810B,0x258D264E,0xDAD39DED,0x75D0B694,0x98CE1216,
  0x93334482,0xC5C48EA5,0xF57E0E8B,0x5D7F3723,0x396B1B24,0xA8883D9F,0xB2A74A00,
  0xF8E171AE,0x3F01FBAB,0x5C1840CB,0xDDD833C4,0x8D8CCA34,0x32EF223A,0x1A05B871,
  0x9A9B6BFC,0x50406A0C,0xE7E1FC04,0x5E07D7F6,0x80B83660,0x20892A62,0xB2C6FEA6,
  0x6CEC7CAA,0x182F764B,0x3B0353E7,0x57FC2520,0x4B6812D4,0xACB654E4,0x23C75C04,
  0xB1DCD731,0xE3AF0733,0xF2366D39,0xC729671B,0xFF3BE6F2,0xABA37E34,0x3CDAFA38,
  0xAAD18D03,0xA8D35345,0x08E9A92C,0xF9324059,0x42D821BE,0x1BC152DD,0x5588811C,
  0x874A1F9A,0x6E83E9CD,0xDA6F3AF8,0x965D4670,0xA7A565C0,0x68D8A9AF,0xFC8FD8FD,
  0x8FF99FF9,0x4C9B42AE,0x2D066A8D,0x4D1802F7,0x557032B2,0x12BCF371,0xDC29D5AE,
  0x72EA361F,0xE2835B0B,0xDFC58966,0x13B0F34D,0x3FA02BCD,0xBF282E3D,0x7DC877F5,
  0xF4848A32,0x861E35F5,0x7FFA0D7F,0x515F2E4E,0x6B235D5C,0x55F46E24,0x35AD2C99,
  0x072654A8,0x05163F0F,0x9317B11A,0xAED1FC10,0x989444F0,0xDB3E1814,0x446C0CF1,
  0x660BF511,0x2F227D3A,0xFDBA0539,0xC649E621,0x5204D7CE,0x5FA386D0,0xE5F22005,
  0x97B6C8A1,0x4AB69EC2,0x5C7CA70D,0x39A48EC6,0x7BACF378,0x8D0ED3D1,0xE39DE582,
  0xC5FBE2AB,0x37E3D2D0,0x06F44724,0x73144144,0xBA57E905,0xB05B4307,0xAEED8D97,
  0xA68CCAC4,0xE30DA57E,0xED0F194B,0x8C2B9B7A,0x814575D5,0x79588493,0x81D3712A,
  0x3FA892F2,0x80F0BB94,0x44EAF51A,0x4E05F1D4,0xFC69F858,0x775E8D60,0x22B20DD7,
  0x170A87EA,0x1077DE52,0x3D5EC9FB,0x0B6EB1E5,0xF2F9CCAF,0xA76C7DEB,0xD8C2D873,
  0xF438C592,0x6239FEEC,0x26D3D2A9,0x30F6FADF,0x4B2984CC,0x6257F3DA,0x0E0583E2,
  0x143E5E61,0xBB2732BF,0x9653217A,0x027A84EA,0x95C9AE8B,0x89B8B82B,0x9F286485,
  0x29F622FE,0x52A3196B,0x8392D95F,0x33A79167,0xF5DEE92A,0x6E397DB9,0x11931C01,
  0x8DD2CD3B,0xF9E6003D,0xAB955AF4,0xD38725F9,0xDCF6F8AE,0x7667A958,0xE67AD995,
  0xB7CF979A,0xD88EBE5B,0x5BA889F0,0x078BDD90,0x447238F9,0x3135F672,0x187B95A8,
  0x0B7D5751,0xACD59D2A,0x9C5D1929,0x579E5022,0xEA90499B,0x59901800,0x82237DB5,
  0x7A375509,0xACA9A22A,0xEC96E649,0x69339DB0,0x081D0D9B,0xD72FB8B9,0xA4184653,
  0xC057321D,0xED19CAB9,0xB48F1E3E,0xB9DAC51E,0xDAED2FC7,0x7598CBBD,0x208DF346,
  0x044BE6EC,0x1C63E6EB,0xA15F64C1,0xE024A061,0x68309584,0x0758A68D,0xF274E9AE,
  0x0ABEA0CC,0xED4FB267,0x63D6EC46,0x9F28E026,0xF0694A17,0x9D6E9115,0xC4600FAD,
  0x5B121E99,0xD6B4A13B,0xF5364B8A,0x8514B254,0x0182F8DD,0xDB09F90B,0x78C70B32,
  0xD8EC3B02,0x8CD7084D,0xA4439838,0x72F35A3D,0x200B48A5,0xE2351444,0xA5552F5F,
  0xD8C1E746,0x0FE5EF3C,0xB6A47063,0x61F4E68B,0x08FED99B,0x7E461445,0x43CB8380,
  0x28BA03C8,0x21A7A2E2,0x43437ED6,0x2A9E6670,0x89B4A106,0xC6C2F4EE,0x9C4063CC,
  0x2FA0DF6C,0xB54DC409,0xCF01538F,0x616431D7,0x02CB0E4D,0x44FFF425,0xAAD5188E,
  0x0742E9BC,0xFFF41353,0x130F0A15,0x787BDC10,0x4A327B72,0x702989F7,0x5F704798,
  0x8156A1BB,0x2BCA3E74,0x1911A8C4,0x5E1F27D3,0x07949DC7,0xF24C2056,0xB4299EE6,
  0x9C7045D9,0xA8BF6307,0x7454AAD2,0x256425E5,0xD87DEF67,0xCFE95452,0xE7548DF7,
  0xA84956C7,0xD8402C60,0xCFBD0373,0x6B6CDAFE
};


uint32_t hash(
    uint32_t seed,
    uint8_t* buffer,
    int len)
{
  int i;
  uint32_t result = seed;

  for (i = len - 1; i > 0; i--)
  {
    result ^= ROTATE_INT32(byte_to_int32[*buffer], i);
    buffer++;
  }

  result ^= byte_to_int32[*buffer];
  return result;
}


int yr_hash_table_create(
    int size,
    YR_HASH_TABLE** table)
{
  YR_HASH_TABLE* new_table;
  int i;

  new_table = (YR_HASH_TABLE*) yr_malloc(
      sizeof(YR_HASH_TABLE) + size * sizeof(YR_HASH_TABLE_ENTRY*));

  if (new_table == NULL)
    return ERROR_INSUFICIENT_MEMORY;

  new_table->size = size;

  for (i = 0; i < size; i++)
    new_table->buckets[i] = NULL;

  *table = new_table;

  return ERROR_SUCCESS;
}

void yr_hash_table_destroy(
    YR_HASH_TABLE* table,
    YR_HASH_TABLE_FREE_VALUE_FUNC free_value)
{
  YR_HASH_TABLE_ENTRY* entry;
  YR_HASH_TABLE_ENTRY* next_entry;

  if (table == NULL)
    return;

  for (int i = 0; i < table->size; i++)
  {
    entry = table->buckets[i];

    while (entry != NULL)
    {
      next_entry = entry->next;

      if (free_value != NULL)
        free_value(entry->value);

      if (entry->ns != NULL)
        yr_free(entry->ns);

      yr_free(entry->key);
      yr_free(entry);

      entry = next_entry;
    }
  }

  yr_free(table);
}


void* yr_hash_table_lookup(
    YR_HASH_TABLE* table,
    const char* key,
    const char* ns)
{
  YR_HASH_TABLE_ENTRY* entry;
  uint32_t bucket_index;

  bucket_index = hash(0, (uint8_t*) key, strlen(key));

  if (ns != NULL)
    bucket_index = hash(bucket_index, (uint8_t*) ns, strlen(ns));

  bucket_index = bucket_index % table->size;

  entry = table->buckets[bucket_index];

  while (entry != NULL)
  {
    if (strcmp(entry->key, key) == 0 &&
        (entry->ns == ns ||
         strcmp(entry->ns, ns) == 0))
    {
      return entry->value;
    }

    entry = entry->next;
  }

  return NULL;
}

int yr_hash_table_add(
    YR_HASH_TABLE* table,
    const char* key,
    const char* ns,
    void* value)
{
  YR_HASH_TABLE_ENTRY* entry;
  uint32_t bucket_index;

  entry = (YR_HASH_TABLE_ENTRY*) yr_malloc(sizeof(YR_HASH_TABLE_ENTRY));

  if (entry == NULL)
    return ERROR_INSUFICIENT_MEMORY;

  entry->key = yr_strdup(key);

  if (entry->key == NULL)
  {
    yr_free(entry);
    return ERROR_INSUFICIENT_MEMORY;
  }

  if (ns != NULL)
  {
    entry->ns = yr_strdup(ns);

    if (entry->ns == NULL)
    {
      yr_free(entry->key);
      yr_free(entry);

      return ERROR_INSUFICIENT_MEMORY;
    }
  }
  else
  {
    entry->ns = NULL;
  }

  entry->value = value;
  bucket_index = hash(0, (uint8_t*) key, strlen(key));

  if (ns != NULL)
    bucket_index = hash(bucket_index, (uint8_t*) ns, strlen(ns));

  bucket_index = bucket_index % table->size;

  entry->next = table->buckets[bucket_index];
  table->buckets[bucket_index] = entry;

  return ERROR_SUCCESS;
}
