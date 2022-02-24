/*
 * Copyright 2022 Sebastiano Miano <mianosebastiano@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "port_conf.h"

PortConf::PortConf() : if_name_(""), if_index_(0) {}

PortConf::PortConf(const std::string name, int ifindex)
    : if_name_(name), if_index_(ifindex) {}

int PortConf::getIfIndex() {
  return if_index_;
}

std::string PortConf::getIfName() {
  return if_name_;
}

void PortConf::setIfIndex(int ifindex) {
  if_index_ = ifindex;
}

void PortConf::setIfName(const std::string &ifname) {
  if_name_ = ifname;
}