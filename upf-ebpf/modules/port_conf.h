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

#ifndef BESS_MODULES_UPF_BPF_PORT_CONF_H_
#define BESS_MODULES_UPF_BPF_PORT_CONF_H_

#include <string>

class PortConf {
public:
  PortConf();
  PortConf(const std::string name, int ifindex);

  int getIfIndex();
  std::string getIfName();

  void setIfIndex(int ifindex);
  void setIfName(const std::string &ifname);

private:
  std::string if_name_;
  int if_index_;
};

#endif // BESS_MODULES_UPF_BPF_PORT_CONF_H_
