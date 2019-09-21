/*
Copyright (c) 2019. The YARA Authors. All Rights Reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors
may be used to endorse or promote products derived from this software without
specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include "sandbox/collect_matches.h"

#include "libyara/include/yara.h"
#include "sandbox/yara_matches.pb.h"

namespace yara {

int CollectMatches(int message, void* message_data, void* user_data) {
  if (message != CALLBACK_MSG_RULE_MATCHING) {
    return ERROR_SUCCESS;  // There are no matching rules, simply return
  }

  auto* rule = static_cast<YR_RULE*>(message_data);
  YR_META* rule_meta = rule->metas;

  auto* match = reinterpret_cast<YaraMatches*>(user_data)->add_match();
  if (rule->ns != nullptr && rule->ns->name != nullptr) {
    match->mutable_id()->set_rule_namespace(rule->ns->name);
  }
  match->mutable_id()->set_rule_name(rule->identifier);
  while (!META_IS_NULL(rule_meta)) {
    auto* meta = match->add_meta();
    meta->set_identifier(rule_meta->identifier);
    switch (rule_meta->type) {
      case META_TYPE_BOOLEAN:
      case META_TYPE_INTEGER:
        meta->set_int_value(rule_meta->integer);
        break;
      case META_TYPE_STRING:
        meta->set_bytes_value(rule_meta->string);
        break;
    }
    ++rule_meta;
  }

  return ERROR_SUCCESS;
}

}  // namespace yara
