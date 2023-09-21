/*
 * Copyright (C) 2023 The National Security Agency (NSA)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef __JAL__SUB__CALLBACKS__H__
#define __JAL__SUB__CALLBACKS__H__

#include "JalSubMessaging.hpp"
#include "JalSubDigestCalculator.hpp"

// A simple struct to hold the callbacks passed from the JalSubscriber to the
// JalSubNetworkLayer
struct SubscriberCallbacks
{
	std::function<Response(Message&)> messageHandler;
	std::function<enum jal_digest_algorithm(Message&)> getDigestAlgorithm;
	std::function<std::string(Message&)> getPublisherId;
	std::function<ModeType(Message&)> getReceiveMode;
	std::function<void(Message&)> notifyTimeout;
};

#endif
