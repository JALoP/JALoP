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
#include <vector>
#include <string>
#include <sstream>
#include <functional>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "JalSubSession.hpp"
#include "JalSubUtils.hpp"

// Helper function to remove space characters from the beginning of a string
// See https://stackoverflow.com/a/217605 for rtrim and alternate implementations
static void ltrim(std::string& str)
{
	str.erase(str.begin(), std::find_if(str.begin(), str.end(), std::not1(std::ptr_fun<int, int>(std::isspace))));
}

// Helper function to extract comma separated values from headers
static std::vector<std::string> splitOnComma(std::string inStr)
{
	std::vector<std::string> values;
	std::stringstream stream(inStr);

	while(stream.good())
	{
		std::string sub;
		std::getline(stream, sub, ',');
		if(!sub.empty())
		{
			ltrim(sub);
			values.push_back(sub);
		}
	}
	return values;
}

// Helper function to select the highest priority option that is supported
// from a comma separated string
static std::string selectSupportedOption(
	const std::string& css,
	const std::vector<std::string>& supportedOptions)
{
	// Extract the values from the comma separated string
	std::vector<std::string> values = splitOnComma(css);

	// For each value, if it is in our supported list, return it
	for(const auto& value : values)
	{
		if(std::find(supportedOptions.begin(), supportedOptions.end(), value)
			!= supportedOptions.end())
		{
			return value;
		}
	}
	return "";
}

enum jal_digest_algorithm Session::getDigestAlgorithm()
{
	return digestAlgorithm;
}

std::string Session::getPublisherId()
{
	return publisherId;
}

ModeType Session::getReceiveMode()
{
	return config.mode;
}

// shorthand for reducing duplication
Response Session::generateNack(std::string errorMessage)
{
	Response response;
	response.addHeader(HEADER_MESSAGE_TYPE, MSG_INIT_NACK_STR);
	response.addHeader(HEADER_JAL_ERROR_MESSAGE_TYPE, errorMessage);
	return response;
}

// shorthand for reducing duplication
Response Session::generateDigestChallenge()
{
	Response response;
	response.addHeader(HEADER_MESSAGE_TYPE, MSG_DIGEST_CHALLENGE_STR);
	response.addHeader(HEADER_JAL_ID_TYPE, currentRecordInfo.jalId);
	response.addHeader(HEADER_JAL_DIGEST_VALUE, currentRecordInfo.digest);
	return response;
}

// shorthand for reducing duplication
Response Session::generateRecordFailure(std::string errorMessage, std::string jalId)
{
	debugOutput(config.debug, stderr, "generating record failure\n");

	Response response;
	response.addHeader(HEADER_MESSAGE_TYPE, MSG_RECORD_FAILURE_STR);
	response.addHeader(HEADER_JAL_ID_TYPE, jalId);
	response.addHeader(HEADER_JAL_ERROR_MESSAGE_TYPE, errorMessage);
	return response;
}

// shorthand for reducing duplication
Response Session::generateSyncFailure()
{
	debugOutput(config.debug, stderr, "generating sync failure\n");
	Response response;
	response.addHeader(HEADER_MESSAGE_TYPE, MSG_SYNC_FAILURE_STR);
	response.addHeader(HEADER_JAL_ID_TYPE, currentRecordInfo.jalId);
	response.addHeader(HEADER_JAL_ERROR_MESSAGE_TYPE, JAL_SYNC_FAILURE);
	return response;
}

// Check if an in-progress journal payload already exists for the publisherId
// with which this session was initialized
bool Session::shouldResume()
{
	// Only resume for journal recordTypes in the archive mode
	if(RecordType::JAL_JOURNAL != recordType ||
		ModeType::ARCHIVE != config.mode )
	{
		debugOutput(config.debug, stdout, "should not resume, type or mode\n");
		return false;
	}

	// TODO: The fact that we need a static member value from the Message class here implies
	// that that's not the right place for the tempFilePath to be stored
	// Build the name for the journal staging directory for this publisher
	std::string dirName = Message::getTempFilePath() + "/" +
		publisherId + "/journal/";

	// The following copied almost verbatim from the scandir(3) manpage
	struct dirent** namelist = NULL;
	int numEntries;

	// alphasort is included in the dirent.h include
	numEntries = scandir(dirName.c_str(), &namelist, NULL, alphasort);

	if(-1 == numEntries)
	{
		// This isn't unusual. The directory for this publisher may not have been created yet
		return false;
	}

	// If there were no files, there's nothing to resume
	if(0 == numEntries)
	{
		for(int i = 0; i < numEntries; i++)
		{
			free(namelist[i]);
		}
		free(namelist);
		return false;
	}

	// From the spec, the oldest non-synced record should be our target for the resume
	// Since our sync process involves removing it from the staging directory, we can just
	// take the oldest record based on the timestamp portion of the record id. Since these
	// files will all have the same publisherId, and are sorted alphabetically, we can
	// just take the first one from our list
	std::string resumeFilePath;
	std::string filename;

	// TODO: Some day we'll want to support multiple resumes. For now, we're deleting
	// any in progress files aside from the first one per the spec.
	struct stat fileStat;
	for(int i = 0; i < numEntries; i++)
	{
		// Build full path to candidate file
		std::string candidateFilePath = dirName + "/" + namelist[i]->d_name;

		// If the current entry is a directory, ignore it
		stat(candidateFilePath.c_str(), &fileStat);
		if(S_ISDIR(fileStat.st_mode))
		{
			continue;
		}

		// Otherwise, if we haven't yet selected a file for use, use this one
		if(resumeFilePath.empty())
		{
			resumeFilePath = candidateFilePath;
			filename = namelist[i]->d_name;
		}
		else
		{
			// If we already selected a file to resume, remove all the rest
			remove(candidateFilePath.c_str());
			debugOutput(config.debug, stdout,
				"shouldResume(): removing payload file: %s\n", candidateFilePath.c_str());
		}
	}

	// We're done with the file list, clean it up
	for(int i = 0; i < numEntries; i++)
	{
		free(namelist[i]);
	}
	free(namelist);

	// It's possible all the results were filtered out because they were directories
	// only continue if we actually selected a payload file
	if(filename.empty() || resumeFilePath.empty())
	{
		return false;
	}

	// Inspect the file to determine its length. This is our offset
	std::ifstream resumeFile(resumeFilePath, std::ios::binary);
	size_t offset = 0;
	if(!resumeFile)
	{
		// Something odd happened, possibly permission related. Attempt to remove the file so
		// we don't repeat this failure in later initializations
		// However there isn't much we can do if the problem is permission related
		remove(resumeFilePath.c_str());
		fprintf(stderr, "Error inspecting payload file, removing file: %s\n",
			resumeFilePath.c_str());
	}
	else
	{
		resumeFile.seekg(0, resumeFile.end);
		offset = resumeFile.tellg();
		debugOutput(config.debug, stdout, "resume offset: %zu\n", offset);
	}
	resumeFile.close();

	// If we got a valid name and offset, use those values for a resume
	if(0 != offset)
	{
		resumeId = filename;
		resumeOffset = offset;
		return true;
	}
	else
	{
		// Otherwise, indicate no resume
		return false;
	}
}

bool Session::validateAndStorePublisherId(const Message& message)
{
	std::string publisherIdString = message.getHeader(HEADER_JAL_PUBLISHER_ID_TYPE);

	if(!publisherIdString.empty())
	{
		publisherId = publisherIdString;
	}
	else
	{
		return false;
	}

	// A UUID should have:
	// length: 36
	// "-" at inxex 8, 13, 18, 23
	// All others should be hex digits
	// Technically there is some additional restriction based on the encoding
	// of the version of UUID, but this should be good enough for a sanity check
	static const std::regex expression("^" // start of string
		"[0-9a-f]{8}" // 8 hex characters
		"-" // literal -
		"[0-9a-f]{4}" // 4 hex characters
		"-" // literal -
		"[0-9a-f]{4}" // 4 hex characters
		"-" // literal -
		"[0-9a-f]{4}" // 4 hex characters
		"-" // literal -
		"[0-9a-f]{12}"
		"$" // end of string
		, std::regex_constants::icase); // ignore case

	if(!std::regex_match(publisherId, expression))
	{
		return false;
	}
	return true;
}

bool Session::validateVersion(const Message& message)
{
	std::string version = message.getHeader(HEADER_JAL_VERSION_TYPE);
	if(version.empty())
	{
		return false;
	}

	for(const auto& allowedVersion : SUPPORTED_VERSIONS)
	{
		if(allowedVersion == version)
		{
			return true;
		}
	}
	return false;
}

bool Session::validateAndStoreXmlCompression(const Message& message)
{
	//TODO
	(void)message;
	return true;
}

bool Session::validateAndStoreAcceptDigest(const Message& message)
{
	// From table 9 in the spec, the sha256 algorithm is required to be supported
	// for an implementation to be compliant, and should be assumed to be selected
	// by the publisher if the header is not provided
	// Note that it is possible for a subscriber to disallow the use of the sha256
	// algorithm using the subscriber configuration
	std::string acceptDigestString = message.getHeader(
		HEADER_JAL_ACCEPT_DIGEST);
	if(acceptDigestString.empty())
	{
		// If no header was found, act as if we received a header with only the default
		// algorithm specified
		debugOutput(config.debug, stdout, "Missing accept digest header. Assuming: %s\n",
			digest_uri_str[JAL_DIGEST_ALGORITHM_DEFAULT]);
		acceptDigestString = digest_uri_str[JAL_DIGEST_ALGORITHM_DEFAULT];
	}

	std::vector<std::string> uriVector;
	for(auto digest_enum : config.allowedConfigureDigest)
	{
		uriVector.push_back(digest_uri_str[digest_enum]);
	}

	// otherwise extract the highest priority supported option
	std::string value = selectSupportedOption(acceptDigestString,
		uriVector);

	if(value.empty())
	{
		// The subscriber does not support any of the provided options
		// Since the parameter was not omitted, we don't fall back to the required sha256
		return false;
	}
	else
	{
		debugOutput(config.debug, stdout, "Session configured with digest algorithm %s\n", value.c_str());
		jal_status err = jal_get_digest_from_uri(value.c_str(), &digestAlgorithm);

		if(JAL_OK != err)
		{
			debugOutput(config.debug, stderr, "Error while parsing digest URI\n");
		}
	}

	return true;
}

bool Session::validateAndStoreAcceptConfigureDigestChallenge(const Message& message)
{
	// From table 10 in the spec, the value of "on" is required
	// to be supported, and should be selected if this optional header is absent
	std::string acceptConfigureDigestChallengeString = message.getHeader(
		HEADER_JAL_ACCEPT_CONFIGURE_DIGEST_CHALLENGE);
	if(acceptConfigureDigestChallengeString.empty())
	{
		shouldChallengeDigest = true;
	}

	// Otherwise, extract the highest priority supported option
	std::string value = selectSupportedOption(acceptConfigureDigestChallengeString,
		SUPPORTED_ACCEPT_CONFIGURE_DIGEST_CHALLENGE);

	if(DIGEST_CHALLENGE_ON == value)
	{
		shouldChallengeDigest = true;
	}
	else if(DIGEST_CHALLENGE_OFF == value)
	{
		shouldChallengeDigest = false;
	}
	else
	{
		// The subscriber does not support any of the provided options
		// Since the parameter was not omitted, we don't fall back to the required "on"
		return false;
	}

	return true;
}

bool Session::validateAndStoreRecordType(const Message& message)
{
	std::string recordString = message.getHeader(HEADER_JAL_RECORD_TYPE);
	if(recordString.empty())
	{
		return false;
	}

	try
	{
		recordType = recordTypeFromString(recordString);
	}
	catch(std::runtime_error &e)
	{
		return false;
	}

	return true;
}

bool Session::validateMode(const Message& message)
{
	std::string modeString = message.getHeader(HEADER_JAL_MODE_TYPE);
	if(modeString.empty())
	{
		return false;
	}

	ModeType publisherMode;
	try
	{
		publisherMode = modeTypeFromHeader(modeString);
	}
	catch(std::runtime_error& e)
	{
		return false;
	}

	if(config.mode != publisherMode)
	{
		return false;
	}
	return true;
}

Response Session::handleAuditMessage(const Message& message)
{
	(void)message;
	//Always print
	fprintf(stdout, "Sending digest challenge for type: audit sessionId: %s\n", uuid.c_str());
	return generateDigestChallenge();
}

Response Session::handleLogMessage(const Message& message)
{
	(void)message;
	//Always print
	fprintf(stdout, "Sending digest challenge for type: log sessionId: %s\n", uuid.c_str());
	return generateDigestChallenge();
}

Response Session::handleJournalMessage(const Message& message)
{
	(void)message;
	//Always print
	fprintf(stdout, "Sending digest challenge for type: journal sessionId: %s\n", uuid.c_str());
	return generateDigestChallenge();
}

Response Session::handleJournalMissing(const Message& message)
{
	// Extract headers
	std::string jalId = message.getHeader(HEADER_JAL_ID_TYPE);
	// The spec doesn't specify what to do if the jalId is missing for this message
	// The publisher respects an empty response, and no errors are defined for this transaction
	// so there's really nothing to do here.
	//
	// If we DO have a jalID, go attempt to clean up the payload corresponding to that ID
	if(!jalId.empty())
	{
		std::string tempFilePath = config.databasePath + "/staging";
		std::string payloadFileName = getPayloadFileName(
			tempFilePath,
			publisherId,
			ReceiveMessageType::MSG_JOURNAL,
			jalId);

		remove(payloadFileName.c_str());
		debugOutput(config.debug, stdout, 
			"handleJournalMissing Removing file: %s\n", payloadFileName.c_str());
	}
	// In either case, send an empty journal-missing-response message
	Response response;
	response.addHeader(HEADER_MESSAGE_TYPE, MSG_JOURNAL_MISSING_RESP_STR);
	return response;
}

Response Session::handleDigestChallengeResponse(const Message& message)
{
	// Extract headers
	std::string jalId = message.getHeader(HEADER_JAL_ID_TYPE);
	// TODO: The spec doesn't specify what to do if the jalId is missing for this message
	// For now, respond with a record failure message with the jalId omitted, I guess?
	if(jalId.empty())
	{
		return generateRecordFailure(JAL_INVALID_JAL_ID, "");
	}

	// Ensure the received JAL_ID matches the record we're working on
	if(jalId != currentRecordInfo.jalId)
	{
		return generateRecordFailure(JAL_INVALID_JAL_ID, jalId);
	}

	DigestStatus status;
	try
	{
		status = digestStatusFromString(message.getHeader(HEADER_JAL_DIGEST_STATUS));
	}
	catch(std::runtime_error& e)
	{
		return generateRecordFailure(JAL_INVALID_DIGEST_STATUS, jalId);
	}

	if(DigestStatus::INVALID == status)
	{
		return generateRecordFailure(JAL_INVALID_DIGEST, jalId);
	}

	auto db = jdb.lock();
	if(!db)
	{
		// This would be extremely unusual and probably implies state corruption of the
		// Subscriber class which contains the db and Sessions
		fprintf(stderr, "Failed to get handle to db interface\n");
		return generateRecordFailure(JAL_RECORD_FAILURE, currentRecordInfo.jalId);
	}


	bool inserted = false;
	switch(recordType)
	{
		case RecordType::JAL_AUDIT:
			debugOutput(config.debug, stdout, "calling insert audit\n");
			inserted = db->insertAudit(currentRecordInfo);
			break;
		case RecordType::JAL_LOG:
			debugOutput(config.debug, stdout, "calling insert log\n");
			inserted = db->insertLog(currentRecordInfo);
			break;
		case RecordType::JAL_JOURNAL:
			debugOutput(config.debug, stdout, "calling insert journal\n");
			inserted = db->insertJournal(currentRecordInfo);
			break;
	}
	
	// Discard the payload file - if any
	// If the file has been moved by the db interface, the remove will fail, which is fine
	// as long as the temporary is gone one way or another
	if(!currentRecordInfo.payloadFileName.empty())
	{
		remove(currentRecordInfo.payloadFileName.c_str());
		debugOutput(config.debug, stdout, "handle digestChallengeResponse removing file: %s\n",
			currentRecordInfo.payloadFileName.c_str());
		currentRecordInfo.payloadFileName.clear();
	}

	if(false == inserted)
	{
		// Always print
		fprintf(stdout, "Sending SYNC failure for jalId: %s\n", currentRecordInfo.jalId.c_str());
		return generateSyncFailure();
	}

	Response response;
	response.addHeader(HEADER_JAL_ID_TYPE, currentRecordInfo.jalId);
	response.addHeader(HEADER_MESSAGE_TYPE, MSG_SYNC_STR);
	// Always print
	fprintf(stdout, "Sending SYNC for jalId: %s\n", currentRecordInfo.jalId.c_str());
	return response;
}

Response Session::handleRecord(const Message& message, RecordType messageRecordType)
{
	// Audit, Log, and Journal record messages have similar information except for
	// the additional AuditFormat header on audit messages.
	// The other notable difference is that the name of the payload header varies
	// Process these common headers and store them in the Session's currentRecordInfo

	// Some headers were already pre-processed
	// in the network layer for efficiency reasons and will already be present in
	// the message recordInfo if we made it this far. See Message::addData(...)
	// The pre-processed headers include: jalId, messageType, and metadata/payload lengths
	// Capture the recordInfo generated by this process
	//
	// Note - this invokes a move assignment, stealing the data from the original rather
	// than copying it. The session is now responsible for cleaning up any temporary
	// payload files. It must guarantee that if the session ends, or when the digest
	// challenge response is received, the temporary file is removed regardless of the 
	// success/fail status of the digest
	
	// We're going to cheat a little bit - the move constructor violates the constness
	// of the message, but the const label is useful everywhere else in the chain
	// Fortunately, we know the underlying storage is always a mutable object, so this is legal
	currentRecordInfo = (const_cast<Message&>(message)).getInfo();

	// Set some values based on the type we're dealing with
	std::function<Response(const Message&)> messageHandler;
	switch(messageRecordType)
	{
		case RecordType::JAL_AUDIT:
			messageHandler = std::bind(&Session::handleAuditMessage, this, std::placeholders::_1);
			break;
		case RecordType::JAL_LOG:
			messageHandler = std::bind(&Session::handleLogMessage, this, std::placeholders::_1);
			break;
		case RecordType::JAL_JOURNAL:
			messageHandler = std::bind(&Session::handleJournalMessage, this, std::placeholders::_1);
			break;
		default:
			// Shouldn't be possible to reach
			fprintf(stderr, "Unreachable code reached in Session::handleRecord. "
				"Generating Record Failure response\n");
			return generateRecordFailure(JAL_UNSUPPORTED_RECORD_TYPE, currentRecordInfo.jalId);
			break;
	}

	// Defer to the appropriate specific function based on message type
	return messageHandler(message);
}

Response Session::handleInitMessage(const Message& message)
{
	// From the spec, the following headers are valid for an initialize message
	// JAL-Publisher-Id
	// JAL-Version
	// TODO: JAL-Accept-XML-Compression, optional
	// JAL-Accept-Digest, optional
	// JAL-Accept-Configure-Digest-Challenge, optional
	// JAL-Record-Type
	// JAL-Mode

	// Store the publisher ID for checking against later messages
	// Validate that it looks like a UUID
	if(!validateAndStorePublisherId(message))
	{
		return generateNack(JAL_UNSUPPORTED_PUBLISHER_ID);
	}

	if(!validateVersion(message))
	{
		return generateNack(JAL_UNSUPPORTED_VERSION);
	}

	if(!validateAndStoreXmlCompression(message))
	{
		return generateNack(JAL_UNSUPPORTED_XML_COMPRESSION);
	}

	if(!validateAndStoreAcceptDigest(message))
	{
		return generateNack(JAL_UNSUPPORTED_DIGEST);
	}

	if(!validateAndStoreAcceptConfigureDigestChallenge(message))
	{
		return generateNack(JAL_UNSUPPORTED_CONFIGURE_DIGEST_CHALLENGE);
	}

	if(!validateAndStoreRecordType(message))
	{
		return generateNack(JAL_UNSUPPORTED_RECORD_TYPE);
	}

	if(!validateMode(message))
	{
		return generateNack(JAL_UNSUPPORTED_MODE);
	}

	Response response;

	if(shouldResume())
	{
		response.addHeader(HEADER_JAL_ID_TYPE, this->resumeId);
		response.addHeader(HEADER_JAL_JOURNAL_OFFSET, std::to_string(this->resumeOffset));
	}

	response.addHeader(HEADER_MESSAGE_TYPE, MSG_INIT_ACK_STR);
	response.addHeader(HEADER_JAL_SESSION_ID_TYPE, uuid);

	// TODO - override default Xml compression
	response.addHeader("JAL-XML-Compression", "None");
	response.addHeader(HEADER_JAL_DIGEST, digest_uri_str[digestAlgorithm]);

	if(shouldChallengeDigest)
	{
		response.addHeader(HEADER_JAL_CONFIGURE_DIGEST_CHALLENGE, DIGEST_CHALLENGE_ON);
	}
	else
	{
		response.addHeader(HEADER_JAL_CONFIGURE_DIGEST_CHALLENGE, DIGEST_CHALLENGE_OFF);
	}

	//Always print
	fprintf(stdout, "Initialized session with type: %s, sessionId: %s\n",
		message.getHeader(HEADER_JAL_RECORD_TYPE).c_str(),  uuid.c_str());

	return response;
}

Response Session::handleCloseMessage(const Message& message)
{
	// Message is not needed here
	(void)message;
	Response response;
	response.addHeader(HEADER_MESSAGE_TYPE, MSG_CLOSE_SESSION_RESP_STR);

	//Always print
	fprintf(stdout, "Session with sessionId: %s closing\n", uuid.c_str());
	return response;
}

Response Session::handleMessage(ReceiveMessageType type, const Message& message)
{
	// Update last-access time
	lastAccess = std::chrono::steady_clock::now();
	switch(type)
	{
		case(ReceiveMessageType::MSG_INIT):
			debugOutput(config.debug, stdout, "handle init\n");
			return handleInitMessage(message);
			break;
		case(ReceiveMessageType::MSG_LOG):
			debugOutput(config.debug, stdout, "handle log\n");
			return handleRecord(message, RecordType::JAL_LOG);
			break;
		case(ReceiveMessageType::MSG_AUDIT):
			debugOutput(config.debug, stdout, "handle audit\n");
			return handleRecord(message, RecordType::JAL_AUDIT);
			break;
		case(ReceiveMessageType::MSG_JOURNAL):
			debugOutput(config.debug, stdout, "handle journal\n");
			return handleRecord(message, RecordType::JAL_JOURNAL);
			break;
		case(ReceiveMessageType::MSG_JOURNAL_MISSING):
			debugOutput(config.debug, stdout, "handle journal missing\n");
			return handleJournalMissing(message);
			break;
		case(ReceiveMessageType::MSG_DIGEST_CHALLENGE_RESP):
			debugOutput(config.debug, stdout, "handle digest challenge resp\n");
			return handleDigestChallengeResponse(message);
			break;
		case(ReceiveMessageType::MSG_CLOSE_SESSION):
			debugOutput(config.debug, stdout, "handle msg close\n");
			return handleCloseMessage(message);
			break;
		case(ReceiveMessageType::UNKNOWN_MESSAGE):
			debugOutput(config.debug, stderr, "handle other\n");
			throw std::runtime_error("Caught unknown message type");
			break;
		default:
			debugOutput(config.debug, stderr, "default case for handle\n");
			throw std::runtime_error("Caught unknown message type");
			break;
	}
}

Session::Session(
	std::string paramUuid,
	std::weak_ptr<JalSubDatabase> paramJdb, 
	SubscriberConfig paramConfig) : uuid(paramUuid), jdb(paramJdb), config(paramConfig)
{
}

Session::~Session()
{
}

std::chrono::time_point<std::chrono::steady_clock> Session::getLastAccess() const
{
	return lastAccess;
}
