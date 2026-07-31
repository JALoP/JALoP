#include <axl.h>
#include <string>
#include <map>
#include "jalop_protocol.hpp"
extern "C" {
	#include <test-dept.h>
	#include "jaln_digest.h"
	#include "jaln_context.h"
	#include "jaln_compression.h"
}

// Typical configuration, used for all tests except where specified for
// specific test cases
// TODO - replace axlList with ANYTHING else
axlList* nominalAllowedDigestAlgs;
axlList* nominalAllowedCompressions;
enum jaln_digest_challenge nominalAllowedChallenge = JALN_DC_PREF_ON;

extern "C" void  setup()
{
	nominalAllowedCompressions = axl_list_new(axl_list_equal_string, axl_free);
	axl_list_append(nominalAllowedCompressions, strdup("None"));

	nominalAllowedDigestAlgs = axl_list_new(jaln_digest_list_equal_func, jaln_digest_list_destroy);
	struct jal_digest_ctx *dctx = jal_digest_ctx_create(JAL_DIGEST_ALGORITHM_SHA256);
	axl_list_append(nominalAllowedDigestAlgs, dctx);
	dctx = jal_digest_ctx_create(JAL_DIGEST_ALGORITHM_SHA384);
	axl_list_append(nominalAllowedDigestAlgs, dctx);
	dctx = jal_digest_ctx_create(JAL_DIGEST_ALGORITHM_SHA512);
	axl_list_append(nominalAllowedDigestAlgs, dctx);
	dctx = NULL;

	nominalAllowedChallenge = JALN_DC_PREF_ON;
}

extern "C" void teardown()
{
	axl_list_free(nominalAllowedCompressions);
	axl_list_free(nominalAllowedDigestAlgs);
}

// Test all nominal values for the journal record type
extern "C" void test_create_init_journal()
{
	std::string pubId = "00000000-0000-0000-0000-000000000000";
	std::string expectedDigestStr = std::string(JAL_SHA256_ALGORITHM_URI) + ", "
		+ JAL_SHA384_ALGORITHM_URI + ", "
		+ JAL_SHA512_ALGORITHM_URI;
	try {
		InitMessage initMessage(JALN_ARCHIVE_MODE,
			JALN_RTYPE_JOURNAL,
			pubId,
			nominalAllowedChallenge,
			nominalAllowedDigestAlgs,
			nominalAllowedCompressions);

		assert_equals(std::string(JALN_VERSION), initMessage.headers.at(std::string(JALN_HDRS_VERSION)));
		assert_equals(std::string(JALN_MSG_INIT), initMessage.headers.at(std::string(JALN_HDRS_MESSAGE)));
		assert_equals(pubId, initMessage.headers.at(JALN_HDRS_PUBLISHER_ID));
		assert_equals(std::string(JALN_MSG_PUBLISH_ARCHIVE), initMessage.headers.at(std::string(JALN_HDRS_MODE)));
		assert_equals(std::string(JALN_STR_JOURNAL), initMessage.headers.at(std::string(JALN_HDRS_RECORD_TYPE)));
		assert_equals(expectedDigestStr, initMessage.headers.at(std::string(JALN_HDRS_ACCEPT_DIGEST)));
		assert_equals(std::string("None"), initMessage.headers.at(std::string(JALN_HDRS_ACCEPT_COMPRESSION)));

	} catch(const std::exception& e) {
		// Success if the test doesn't throw
		fprintf(stderr, "Unexpected exception: %s\n", e.what());
		assert_true(false);
	}
}

// Test all nominal values for the audit record type
extern "C" void test_create_init_audit()
{
	std::string pubId = "00000000-0000-0000-0000-000000000000";
	std::string expectedDigestStr = std::string(JAL_SHA256_ALGORITHM_URI) + ", "
		+ JAL_SHA384_ALGORITHM_URI + ", "
		+ JAL_SHA512_ALGORITHM_URI;
	try {
		InitMessage initMessage(JALN_ARCHIVE_MODE,
			JALN_RTYPE_AUDIT,
			pubId,
			nominalAllowedChallenge,
			nominalAllowedDigestAlgs,
			nominalAllowedCompressions);

		assert_equals(std::string(JALN_VERSION), initMessage.headers.at(std::string(JALN_HDRS_VERSION)));
		assert_equals(std::string(JALN_MSG_INIT), initMessage.headers.at(std::string(JALN_HDRS_MESSAGE)));
		assert_equals(pubId, initMessage.headers.at(JALN_HDRS_PUBLISHER_ID));
		assert_equals(std::string(JALN_MSG_PUBLISH_ARCHIVE), initMessage.headers.at(std::string(JALN_HDRS_MODE)));
		assert_equals(std::string(JALN_STR_AUDIT), initMessage.headers.at(std::string(JALN_HDRS_RECORD_TYPE)));
		assert_equals(expectedDigestStr, initMessage.headers.at(std::string(JALN_HDRS_ACCEPT_DIGEST)));
		assert_equals(std::string("None"), initMessage.headers.at(std::string(JALN_HDRS_ACCEPT_COMPRESSION)));

	} catch(const std::exception& e) {
		// Success if the test doesn't throw
		fprintf(stderr, "Unexpected exception: %s\n", e.what());
		assert_true(false);
	}
}

// Test all nominal values for the log record type
extern "C" void test_create_init_log()
{
	std::string pubId = "00000000-0000-0000-0000-000000000000";
	std::string expectedDigestStr = std::string(JAL_SHA256_ALGORITHM_URI) + ", "
		+ JAL_SHA384_ALGORITHM_URI + ", "
		+ JAL_SHA512_ALGORITHM_URI;
	try {
		InitMessage initMessage(JALN_ARCHIVE_MODE,
			JALN_RTYPE_LOG,
			pubId,
			nominalAllowedChallenge,
			nominalAllowedDigestAlgs,
			nominalAllowedCompressions);

		assert_equals(std::string(JALN_VERSION), initMessage.headers.at(std::string(JALN_HDRS_VERSION)));
		assert_equals(std::string(JALN_MSG_INIT), initMessage.headers.at(std::string(JALN_HDRS_MESSAGE)));
		assert_equals(pubId, initMessage.headers.at(JALN_HDRS_PUBLISHER_ID));
		assert_equals(std::string(JALN_MSG_PUBLISH_ARCHIVE), initMessage.headers.at(std::string(JALN_HDRS_MODE)));
		assert_equals(std::string(JALN_STR_LOG), initMessage.headers.at(std::string(JALN_HDRS_RECORD_TYPE)));
		assert_equals(expectedDigestStr, initMessage.headers.at(std::string(JALN_HDRS_ACCEPT_DIGEST)));
		assert_equals(std::string("None"), initMessage.headers.at(std::string(JALN_HDRS_ACCEPT_COMPRESSION)));

	} catch(const std::exception& e) {
		// Success if the test doesn't throw
		fprintf(stderr, "Unexpected exception: %s\n", e.what());
		assert_true(false);
	}
}

extern "C" void test_create_init_no_cmp()
{
	std::string pubId = "00000000-0000-0000-0000-000000000000";
	axlList *empty_list = axl_list_new(jaln_string_list_case_insensitive_func, free);
	try {
		InitMessage initMessage(JALN_ARCHIVE_MODE,
			JALN_RTYPE_JOURNAL,
			pubId,
			nominalAllowedChallenge,
			nominalAllowedDigestAlgs,
			empty_list);

		try {
			// Ensure the JALN_HDRS_ACCEPT_COMPRESSION header was not populated
			assert_equals(std::string("None"), initMessage.headers.at(std::string(JALN_HDRS_ACCEPT_COMPRESSION)));
			assert_true(false);
		} catch (const std::out_of_range& e) {
			// We expect this exception, no action
			assert_true(true);
		}
	} catch(const std::exception& e) {
		// Success if the test doesn't throw
		fprintf(stderr, "Unexpected exception: %s\n", e.what());
		assert_true(false);
	}
	axl_list_free(empty_list);
}

// The JALN_HDRS_ACCEPT_DIGEST may be omitted
extern "C" void test_create_init_no_digest()
{
	std::string pubId = "00000000-0000-0000-0000-000000000000";
	axlList *empty_list = axl_list_new(jaln_string_list_case_insensitive_func, free);
	try {
		InitMessage initMessage(JALN_ARCHIVE_MODE,
			JALN_RTYPE_JOURNAL,
			pubId,
			nominalAllowedChallenge,
			empty_list,
			nominalAllowedCompressions);

		try {
			// Ensure the JALN_HDRS_ACCEPT_DIGEST header was not populated
			initMessage.headers.at(std::string(JALN_HDRS_ACCEPT_DIGEST));
			assert_true(false);
		} catch (const std::out_of_range& e) {
			// We expect this exception, no action
			assert_true(true);
		}
	} catch(const std::exception& e) {
		// Success if the test doesn't throw
		fprintf(stderr, "Unexpected exception: %s\n", e.what());
		assert_true(false);
	}
	axl_list_free(empty_list);
}

extern "C" void test_create_init_challenge_on()
{
	std::string pubId = "00000000-0000-0000-0000-000000000000";
	try {
		InitMessage initMessage(JALN_ARCHIVE_MODE,
			JALN_RTYPE_JOURNAL,
			pubId,
			JALN_DC_ON,
			nominalAllowedDigestAlgs,
			nominalAllowedCompressions);

		assert_equals(std::string("on"), initMessage.headers.at(std::string(JALN_HDRS_ACCEPT_CONFIGURE_DIGEST_CHALLENGE)));

	} catch(const std::exception& e) {
		// Success if the test doesn't throw
		fprintf(stderr, "Unexpected exception: %s\n", e.what());
		assert_true(false);
	}
}

extern "C" void test_create_init_challenge_off()
{
	std::string pubId = "00000000-0000-0000-0000-000000000000";
	try {
		InitMessage initMessage(JALN_ARCHIVE_MODE,
			JALN_RTYPE_JOURNAL,
			pubId,
			JALN_DC_OFF,
			nominalAllowedDigestAlgs,
			nominalAllowedCompressions);

		assert_equals(std::string("off"), initMessage.headers.at(std::string(JALN_HDRS_ACCEPT_CONFIGURE_DIGEST_CHALLENGE)));

	} catch(const std::exception& e) {
		// Success if the test doesn't throw
		fprintf(stderr, "Unexpected exception: %s\n", e.what());
		assert_true(false);
	}
}

extern "C" void test_create_init_challenge_pref_on()
{
	std::string pubId = "00000000-0000-0000-0000-000000000000";
	try {
		InitMessage initMessage(JALN_ARCHIVE_MODE,
			JALN_RTYPE_JOURNAL,
			pubId,
			JALN_DC_PREF_ON,
			nominalAllowedDigestAlgs,
			nominalAllowedCompressions);

		assert_equals(std::string("on, off"), initMessage.headers.at(std::string(JALN_HDRS_ACCEPT_CONFIGURE_DIGEST_CHALLENGE)));

	} catch(const std::exception& e) {
		// Success if the test doesn't throw
		fprintf(stderr, "Unexpected exception: %s\n", e.what());
		assert_true(false);
	}
}

extern "C" void test_create_init_challenge_pref_off()
{
	std::string pubId = "00000000-0000-0000-0000-000000000000";
	try {
		InitMessage initMessage(JALN_ARCHIVE_MODE,
			JALN_RTYPE_JOURNAL,
			pubId,
			JALN_DC_PREF_OFF,
			nominalAllowedDigestAlgs,
			nominalAllowedCompressions);

		assert_equals(std::string("off, on"), initMessage.headers.at(std::string(JALN_HDRS_ACCEPT_CONFIGURE_DIGEST_CHALLENGE)));

	} catch(const std::exception& e) {
		// Success if the test doesn't throw
		fprintf(stderr, "Unexpected exception: %s\n", e.what());
		assert_true(false);
	}
}

extern "C" void test_create_init_throws_on_bad_input()
{
	std::string pubId = "00000000-0000-0000-0000-000000000000";
	try {
		// Illegal value for mode
		InitMessage initMessage(
			(enum jaln_publish_mode)(JALN_ARCHIVE_MODE - 1),
			JALN_RTYPE_JOURNAL,
			pubId,
			nominalAllowedChallenge,
			nominalAllowedDigestAlgs,
			nominalAllowedCompressions);
		// Failure if the test doesn't throw and reaches this line
		assert_true(false);
	} catch(const InvalidMessage& e) {
		// Success if the test throws
		assert_true(true);
	}

	try {
		// Illegal value for type
		InitMessage initMessage(
			JALN_ARCHIVE_MODE,
			(enum jaln_record_type)(JALN_RTYPE_JOURNAL | JALN_RTYPE_AUDIT),
			pubId,
			nominalAllowedChallenge,
			nominalAllowedDigestAlgs,
			nominalAllowedCompressions);
		// Failure if the test doesn't throw and reaches this line
		assert_true(false);
	} catch(const InvalidMessage& e) {
		// Success if the test throws
		assert_true(true);
	}

	try {
		// Illegal value for publisher ID
		InitMessage initMessage(
			JALN_ARCHIVE_MODE,
			JALN_RTYPE_JOURNAL,
			"",
			nominalAllowedChallenge,
			nominalAllowedDigestAlgs,
			nominalAllowedCompressions);
		// Failure if the test doesn't throw and reaches this line
		assert_true(false);
	} catch(const InvalidMessage& e) {
		// Success if the test throws
		assert_true(true);
	}
}

extern "C" void test_get_response_type()
{
	JalopResponse response;
	response.headers = {
		{JALN_HDRS_VERSION, JALN_VERSION},
		{JALN_HDRS_CONTENT_TYPE, JALN_STR_CT_JALOP},
		{JALN_HDRS_CONTENT_LENGTH, "0"},
		{JALN_HDRS_MESSAGE, JALN_MSG_INIT_ACK},
	};

	try {
		auto response_type = response.getResponseType();
		assert_equals(ResponseType::InitAck, response_type);
	} catch(const MalformedResponse& e) {
		fprintf(stderr, "Unexpected exception: %s\n", e.what());
		assert_true(false);
	}
}

extern "C" void test_get_response_type_missing_content_type()
{
	JalopResponse response;
	response.headers = {
		{JALN_HDRS_VERSION, JALN_VERSION},
		{JALN_HDRS_CONTENT_LENGTH, "0"},
		{JALN_HDRS_MESSAGE, JALN_MSG_INIT_ACK},
	};

	try {
		response.getResponseType();
		fprintf(stderr, "getResponseType failed to throw with missing content type\n");
		assert_true(false);
	} catch(const MalformedResponse& e) {
		assert_true(true);
	}
}

extern "C" void test_get_response_type_invalid_content_type()
{
	JalopResponse response;
	response.headers = {
		{JALN_HDRS_VERSION, JALN_VERSION},
		{JALN_HDRS_CONTENT_TYPE, "application/other"},
		{JALN_HDRS_CONTENT_LENGTH, "0"},
		{JALN_HDRS_MESSAGE, JALN_MSG_INIT_ACK},
	};

	try {
		response.getResponseType();
		fprintf(stderr, "getResponseType failed to throw with invalid content type\n");
		assert_true(false);
	} catch(const MalformedResponse& e) {
		assert_true(true);
	}
}

extern "C" void test_get_response_type_missing_message_type()
{
	JalopResponse response;
	response.headers = {
		{JALN_HDRS_VERSION, JALN_VERSION},
		{JALN_HDRS_CONTENT_TYPE, JALN_STR_CT_JALOP},
		{JALN_HDRS_CONTENT_LENGTH, "0"},
	};

	try {
		response.getResponseType();
		fprintf(stderr, "getResponseType failed to throw with missing message type\n");
		assert_true(false);
	} catch(const MalformedResponse& e) {
		assert_true(true);
	}
}

extern "C" void test_get_response_type_invalid_message_type()
{
	JalopResponse response;
	response.headers = {
		{JALN_HDRS_VERSION, JALN_VERSION},
		{JALN_HDRS_CONTENT_TYPE, JALN_STR_CT_JALOP},
		{JALN_HDRS_CONTENT_LENGTH, "0"},
		{JALN_HDRS_MESSAGE, "OtherMessage"},
	};

	try {
		response.getResponseType();
		fprintf(stderr, "getResponseType failed to throw with invalid message type\n");
		assert_true(false);
	} catch(const MalformedResponse& e) {
		assert_true(true);
	}
}

extern "C" void test_parse_init_ack_nominal()
{
	std::string sessionId = "00000000-0000-0000-0000-000000000000";
	std::string recordId = "11111111-1111-1111-1111-111111111111";
	const std::map<std::string, std::string> headers = {
		{JALN_HDRS_VERSION, JALN_VERSION},
		{JALN_HDRS_CONTENT_TYPE, JALN_STR_CT_JALOP},
		{JALN_HDRS_CONTENT_LENGTH, "0"},
		{JALN_HDRS_MESSAGE, JALN_MSG_INIT_ACK},
		{JALN_HDRS_SESSION_ID, sessionId},
		{JALN_HDRS_COMPRESSION, "None"},
		{JALN_HDRS_DIGEST, JAL_SHA256_ALGORITHM_URI},
		{JALN_HDRS_CONFIGURE_DIGEST_CHALLENGE, JALN_DIGEST_CHALLENGE_ON},
		{JALN_HDRS_ID, recordId},
		{JALN_HDRS_JOURNAL_OFFSET, "100"},
	};

	struct JalopResponse response;
	response.headers = headers;

	enum jaln_publish_mode mode = JALN_ARCHIVE_MODE;
	enum jaln_record_type type = JALN_RTYPE_JOURNAL;

	try {
		assert_equals(ResponseType::InitAck, response.getResponseType());
		InitAck initAck(response,
			nominalAllowedDigestAlgs,
			nominalAllowedCompressions,
			nominalAllowedChallenge,
			mode,
			type);

		assert_equals(initAck.sessionId, sessionId);
		assert_equals(initAck.xmlCompression, std::string("None"));
		assert_equals(initAck.digestAlgorithm, JAL_DIGEST_ALGORITHM_SHA256);
		assert_equals(initAck.digestAlgorithmUri, JAL_SHA256_ALGORITHM_URI);
		assert_equals(initAck.challengeDigest, true);
		assert_equals(initAck.id, recordId);
		assert_equals(100, initAck.offset);
	} catch(std::exception& e) {
		fprintf(stderr, "Unexpected exception: %s\n", e.what());
		assert_true(false);
	}
}

extern "C" void test_parse_init_ack_with_content()
{
	const std::map<std::string, std::string> headers = {
		{JALN_HDRS_VERSION, JALN_VERSION},
		{JALN_HDRS_CONTENT_TYPE, JALN_STR_CT_JALOP},
		{JALN_HDRS_CONTENT_LENGTH, "123"},
		{JALN_HDRS_MESSAGE, JALN_MSG_INIT_ACK},
		{JALN_HDRS_SESSION_ID, "00000000-0000-0000-0000-000000000000"},
		{JALN_HDRS_COMPRESSION, "None"},
		{JALN_HDRS_DIGEST, JAL_SHA256_ALGORITHM_URI},
		{JALN_HDRS_CONFIGURE_DIGEST_CHALLENGE, JALN_DIGEST_CHALLENGE_ON},
	};

	struct JalopResponse response;
	response.headers = headers;

	enum jaln_publish_mode mode = JALN_ARCHIVE_MODE;
	enum jaln_record_type type = JALN_RTYPE_JOURNAL;

	try {
		assert_equals(ResponseType::InitAck, response.getResponseType());
		InitAck initAck(response,
			nominalAllowedDigestAlgs,
			nominalAllowedCompressions,
			nominalAllowedChallenge,
			mode,
			type);

		fprintf(stderr, "InitAck constructor failed to throw with non-zero content length\n");
		assert_true(false);
	} catch(const InvalidResponse& e) {
		assert_true(true);
	}
}

extern "C" void test_parse_init_ack_missing_sesion_id()
{
	const std::map<std::string, std::string> headers = {
		{JALN_HDRS_VERSION, JALN_VERSION},
		{JALN_HDRS_CONTENT_TYPE, JALN_STR_CT_JALOP},
		{JALN_HDRS_CONTENT_LENGTH, "0"},
		{JALN_HDRS_MESSAGE, JALN_MSG_INIT_ACK},
		{JALN_HDRS_COMPRESSION, "None"},
		{JALN_HDRS_DIGEST, JAL_SHA256_ALGORITHM_URI},
		{JALN_HDRS_CONFIGURE_DIGEST_CHALLENGE, JALN_DIGEST_CHALLENGE_ON},
	};

	struct JalopResponse response;
	response.headers = headers;

	enum jaln_publish_mode mode = JALN_ARCHIVE_MODE;
	enum jaln_record_type type = JALN_RTYPE_JOURNAL;

	try {
		assert_equals(ResponseType::InitAck, response.getResponseType());
		InitAck initAck(response,
			nominalAllowedDigestAlgs,
			nominalAllowedCompressions,
			nominalAllowedChallenge,
			mode,
			type);

		fprintf(stderr, "InitAck constructor failed to throw with missing session id\n");
		assert_true(false);
	} catch(const InvalidResponse& e) {
		assert_true(true);
	}
}

extern "C" void test_parse_init_ack_missing_compression()
{
	const std::map<std::string, std::string> headers = {
		{JALN_HDRS_VERSION, JALN_VERSION},
		{JALN_HDRS_CONTENT_TYPE, JALN_STR_CT_JALOP},
		{JALN_HDRS_CONTENT_LENGTH, "0"},
		{JALN_HDRS_MESSAGE, JALN_MSG_INIT_ACK},
		{JALN_HDRS_SESSION_ID, "00000000-0000-0000-0000-000000000000"},
		{JALN_HDRS_DIGEST, JAL_SHA256_ALGORITHM_URI},
		{JALN_HDRS_CONFIGURE_DIGEST_CHALLENGE, JALN_DIGEST_CHALLENGE_ON},
	};

	struct JalopResponse response;
	response.headers = headers;

	enum jaln_publish_mode mode = JALN_ARCHIVE_MODE;
	enum jaln_record_type type = JALN_RTYPE_JOURNAL;

	try {
		assert_equals(ResponseType::InitAck, response.getResponseType());
		InitAck initAck(response,
			nominalAllowedDigestAlgs,
			nominalAllowedCompressions,
			nominalAllowedChallenge,
			mode,
			type);

		fprintf(stderr, "InitAck constructor failed to throw with missing compression\n");
		assert_true(false);
	} catch(const InvalidResponse& e) {
		assert_true(true);
	}
}

extern "C" void test_parse_init_ack_unacceptable_compression()
{
	const std::map<std::string, std::string> headers = {
		{JALN_HDRS_VERSION, JALN_VERSION},
		{JALN_HDRS_CONTENT_TYPE, JALN_STR_CT_JALOP},
		{JALN_HDRS_CONTENT_LENGTH, "0"},
		{JALN_HDRS_MESSAGE, JALN_MSG_INIT_ACK},
		{JALN_HDRS_COMPRESSION, "Some"},
		{JALN_HDRS_DIGEST, JAL_SHA256_ALGORITHM_URI},
		{JALN_HDRS_CONFIGURE_DIGEST_CHALLENGE, JALN_DIGEST_CHALLENGE_ON},
	};

	struct JalopResponse response;
	response.headers = headers;

	enum jaln_publish_mode mode = JALN_ARCHIVE_MODE;
	enum jaln_record_type type = JALN_RTYPE_JOURNAL;

	try {
		assert_equals(ResponseType::InitAck, response.getResponseType());
		InitAck initAck(response,
			nominalAllowedDigestAlgs,
			nominalAllowedCompressions,
			nominalAllowedChallenge,
			mode,
			type);

		fprintf(stderr, "InitAck constructor failed to throw with invalid compression\n");
		assert_true(false);
	} catch(const InvalidResponse& e) {
		assert_true(true);
	}
}

extern "C" void test_parse_init_ack_missing_algorithm()
{
	const std::map<std::string, std::string> headers = {
		{JALN_HDRS_VERSION, JALN_VERSION},
		{JALN_HDRS_CONTENT_TYPE, JALN_STR_CT_JALOP},
		{JALN_HDRS_CONTENT_LENGTH, "0"},
		{JALN_HDRS_MESSAGE, JALN_MSG_INIT_ACK},
		{JALN_HDRS_COMPRESSION, "None"},
		{JALN_HDRS_CONFIGURE_DIGEST_CHALLENGE, JALN_DIGEST_CHALLENGE_ON},
	};

	struct JalopResponse response;
	response.headers = headers;

	enum jaln_publish_mode mode = JALN_ARCHIVE_MODE;
	enum jaln_record_type type = JALN_RTYPE_JOURNAL;

	try {
		assert_equals(ResponseType::InitAck, response.getResponseType());
		InitAck initAck(response,
			nominalAllowedDigestAlgs,
			nominalAllowedCompressions,
			nominalAllowedChallenge,
			mode,
			type);

		fprintf(stderr, "InitAck constructor failed to throw with missing algorithm\n");
		assert_true(false);
	} catch(const InvalidResponse& e) {
		assert_true(true);
	}
}

extern "C" void test_parse_init_ack_invalid_algorithm()
{
	const std::map<std::string, std::string> headers = {
		{JALN_HDRS_VERSION, JALN_VERSION},
		{JALN_HDRS_CONTENT_TYPE, JALN_STR_CT_JALOP},
		{JALN_HDRS_CONTENT_LENGTH, "0"},
		{JALN_HDRS_MESSAGE, JALN_MSG_INIT_ACK},
		{JALN_HDRS_COMPRESSION, "None"},
		{JALN_HDRS_DIGEST, "badalg"},
		{JALN_HDRS_CONFIGURE_DIGEST_CHALLENGE, JALN_DIGEST_CHALLENGE_ON},
	};

	struct JalopResponse response;
	response.headers = headers;

	enum jaln_publish_mode mode = JALN_ARCHIVE_MODE;
	enum jaln_record_type type = JALN_RTYPE_JOURNAL;

	try {
		assert_equals(ResponseType::InitAck, response.getResponseType());
		InitAck initAck(response,
			nominalAllowedDigestAlgs,
			nominalAllowedCompressions,
			nominalAllowedChallenge,
			mode,
			type);

		fprintf(stderr, "InitAck constructor failed to throw with invalid algorithm\n");
		assert_true(false);
	} catch(const InvalidResponse& e) {
		assert_true(true);
	}
}

extern "C" void test_parse_init_ack_valid_unaccepted_algorithm()
{
	const std::map<std::string, std::string> headers = {
		{JALN_HDRS_VERSION, JALN_VERSION},
		{JALN_HDRS_CONTENT_TYPE, JALN_STR_CT_JALOP},
		{JALN_HDRS_CONTENT_LENGTH, "0"},
		{JALN_HDRS_MESSAGE, JALN_MSG_INIT_ACK},
		{JALN_HDRS_COMPRESSION, "None"},
		{JALN_HDRS_DIGEST, JAL_SHA256_ALGORITHM_URI},
		{JALN_HDRS_CONFIGURE_DIGEST_CHALLENGE, JALN_DIGEST_CHALLENGE_ON},
	};

	struct JalopResponse response;
	response.headers = headers;

	enum jaln_publish_mode mode = JALN_ARCHIVE_MODE;
	enum jaln_record_type type = JALN_RTYPE_JOURNAL;

	axlList* acceptedAlgs = axl_list_new(jaln_digest_list_equal_func, jaln_digest_list_destroy);
	struct jal_digest_ctx *dctx = jal_digest_ctx_create(JAL_DIGEST_ALGORITHM_SHA384);
	axl_list_append(acceptedAlgs, dctx);
	dctx = NULL;

	try {
		assert_equals(ResponseType::InitAck, response.getResponseType());
		InitAck initAck(response,
			acceptedAlgs,
			nominalAllowedCompressions,
			nominalAllowedChallenge,
			mode,
			type);

		fprintf(stderr, "InitAck constructor failed to throw with unacceptable algorithm\n");
		assert_true(false);
	} catch(const InvalidResponse& e) {
		assert_true(true);
	}
	axl_list_free(acceptedAlgs);
}

extern "C" void test_parse_init_ack_missing_configure_digest()
{
	const std::map<std::string, std::string> headers = {
		{JALN_HDRS_VERSION, JALN_VERSION},
		{JALN_HDRS_CONTENT_TYPE, JALN_STR_CT_JALOP},
		{JALN_HDRS_CONTENT_LENGTH, "0"},
		{JALN_HDRS_MESSAGE, JALN_MSG_INIT_ACK},
		{JALN_HDRS_COMPRESSION, "None"},
		{JALN_HDRS_DIGEST, JAL_SHA256_ALGORITHM_URI},
	};

	struct JalopResponse response;
	response.headers = headers;

	enum jaln_publish_mode mode = JALN_ARCHIVE_MODE;
	enum jaln_record_type type = JALN_RTYPE_JOURNAL;

	try {
		assert_equals(ResponseType::InitAck, response.getResponseType());
		InitAck initAck(response,
			nominalAllowedDigestAlgs,
			nominalAllowedCompressions,
			nominalAllowedChallenge,
			mode,
			type);

		fprintf(stderr, "InitAck constructor failed to throw with missing configure digest\n");
		assert_true(false);
	} catch(const InvalidResponse& e) {
		assert_true(true);
	}
}

extern "C" void test_parse_init_ack_invalid_configure_digest()
{
	const std::map<std::string, std::string> headers = {
		{JALN_HDRS_VERSION, JALN_VERSION},
		{JALN_HDRS_CONTENT_TYPE, JALN_STR_CT_JALOP},
		{JALN_HDRS_CONTENT_LENGTH, "0"},
		{JALN_HDRS_MESSAGE, JALN_MSG_INIT_ACK},
		{JALN_HDRS_COMPRESSION, "None"},
		{JALN_HDRS_DIGEST, JAL_SHA256_ALGORITHM_URI},
		{JALN_HDRS_CONFIGURE_DIGEST_CHALLENGE, "neither"},
	};

	struct JalopResponse response;
	response.headers = headers;

	enum jaln_publish_mode mode = JALN_ARCHIVE_MODE;
	enum jaln_record_type type = JALN_RTYPE_JOURNAL;

	try {
		assert_equals(ResponseType::InitAck, response.getResponseType());
		InitAck initAck(response,
			nominalAllowedDigestAlgs,
			nominalAllowedCompressions,
			nominalAllowedChallenge,
			mode,
			type);

		fprintf(stderr, "InitAck constructor failed to throw with invalid configure digest\n");
		assert_true(false);
	} catch(const InvalidResponse& e) {
		assert_true(true);
	}
}

extern "C" void test_parse_init_ack_mismatched_configure_digest()
{
	const std::map<std::string, std::string> headers = {
		{JALN_HDRS_VERSION, JALN_VERSION},
		{JALN_HDRS_CONTENT_TYPE, JALN_STR_CT_JALOP},
		{JALN_HDRS_CONTENT_LENGTH, "0"},
		{JALN_HDRS_MESSAGE, JALN_MSG_INIT_ACK},
		{JALN_HDRS_COMPRESSION, "None"},
		{JALN_HDRS_DIGEST, JAL_SHA256_ALGORITHM_URI},
		{JALN_HDRS_CONFIGURE_DIGEST_CHALLENGE, "off"},
	};

	struct JalopResponse response;
	response.headers = headers;

	enum jaln_publish_mode mode = JALN_ARCHIVE_MODE;
	enum jaln_record_type type = JALN_RTYPE_JOURNAL;

	try {
		assert_equals(ResponseType::InitAck, response.getResponseType());
		InitAck initAck(response,
			nominalAllowedDigestAlgs,
			nominalAllowedCompressions,
			JALN_DC_ON,
			mode,
			type);

		fprintf(stderr, "InitAck constructor failed to throw with unacceptable configure digest\n");
		assert_true(false);
	} catch(const InvalidResponse& e) {
		assert_true(true);
	}
}

extern "C" void test_parse_init_ack_offset_without_id()
{
	std::string sessionId = "00000000-0000-0000-0000-000000000000";
	const std::map<std::string, std::string> headers = {
		{JALN_HDRS_VERSION, JALN_VERSION},
		{JALN_HDRS_CONTENT_TYPE, JALN_STR_CT_JALOP},
		{JALN_HDRS_CONTENT_LENGTH, "0"},
		{JALN_HDRS_MESSAGE, JALN_MSG_INIT_ACK},
		{JALN_HDRS_SESSION_ID, sessionId},
		{JALN_HDRS_COMPRESSION, "None"},
		{JALN_HDRS_DIGEST, JAL_SHA256_ALGORITHM_URI},
		{JALN_HDRS_CONFIGURE_DIGEST_CHALLENGE, JALN_DIGEST_CHALLENGE_ON},
		{JALN_HDRS_JOURNAL_OFFSET, "100"},
	};

	struct JalopResponse response;
	response.headers = headers;

	enum jaln_publish_mode mode = JALN_ARCHIVE_MODE;
	enum jaln_record_type type = JALN_RTYPE_JOURNAL;

	try {
		assert_equals(ResponseType::InitAck, response.getResponseType());
		InitAck initAck(response,
			nominalAllowedDigestAlgs,
			nominalAllowedCompressions,
			nominalAllowedChallenge,
			mode,
			type);

		fprintf(stderr, "InitAck failed to throw with resume offset without id\n");
		assert_true(false);
	} catch(std::exception& e) {
		assert_true(true);
	}
}

extern "C" void test_parse_init_ack_id_without_offset()
{
	std::string sessionId = "00000000-0000-0000-0000-000000000000";
	std::string recordId = "11111111-1111-1111-1111-111111111111";
	const std::map<std::string, std::string> headers = {
		{JALN_HDRS_VERSION, JALN_VERSION},
		{JALN_HDRS_CONTENT_TYPE, JALN_STR_CT_JALOP},
		{JALN_HDRS_CONTENT_LENGTH, "0"},
		{JALN_HDRS_MESSAGE, JALN_MSG_INIT_ACK},
		{JALN_HDRS_SESSION_ID, sessionId},
		{JALN_HDRS_COMPRESSION, "None"},
		{JALN_HDRS_DIGEST, JAL_SHA256_ALGORITHM_URI},
		{JALN_HDRS_CONFIGURE_DIGEST_CHALLENGE, JALN_DIGEST_CHALLENGE_ON},
		{JALN_HDRS_ID, recordId},
	};

	struct JalopResponse response;
	response.headers = headers;

	enum jaln_publish_mode mode = JALN_ARCHIVE_MODE;
	enum jaln_record_type type = JALN_RTYPE_JOURNAL;

	try {
		assert_equals(ResponseType::InitAck, response.getResponseType());
		InitAck initAck(response,
			nominalAllowedDigestAlgs,
			nominalAllowedCompressions,
			nominalAllowedChallenge,
			mode,
			type);

		fprintf(stderr, "InitAck failed to throw with resume id without offset\n");
		assert_true(false);
	} catch(std::exception& e) {
		assert_true(true);
	}
}

extern "C" void test_parse_init_ack_resume_with_live()
{
	std::string sessionId = "00000000-0000-0000-0000-000000000000";
	std::string recordId = "11111111-1111-1111-1111-111111111111";
	const std::map<std::string, std::string> headers = {
		{JALN_HDRS_VERSION, JALN_VERSION},
		{JALN_HDRS_CONTENT_TYPE, JALN_STR_CT_JALOP},
		{JALN_HDRS_CONTENT_LENGTH, "0"},
		{JALN_HDRS_MESSAGE, JALN_MSG_INIT_ACK},
		{JALN_HDRS_SESSION_ID, sessionId},
		{JALN_HDRS_COMPRESSION, "None"},
		{JALN_HDRS_DIGEST, JAL_SHA256_ALGORITHM_URI},
		{JALN_HDRS_CONFIGURE_DIGEST_CHALLENGE, JALN_DIGEST_CHALLENGE_ON},
		{JALN_HDRS_ID, recordId},
		{JALN_HDRS_JOURNAL_OFFSET, "100"},
	};

	struct JalopResponse response;
	response.headers = headers;

	enum jaln_publish_mode mode = JALN_LIVE_MODE;
	enum jaln_record_type type = JALN_RTYPE_JOURNAL;

	try {
		assert_equals(ResponseType::InitAck, response.getResponseType());
		InitAck initAck(response,
			nominalAllowedDigestAlgs,
			nominalAllowedCompressions,
			nominalAllowedChallenge,
			mode,
			type);

		fprintf(stderr, "InitAck failed to throw with resume in live mode\n");
		assert_true(false);
	} catch(std::exception& e) {
		assert_true(true);
	}
}

extern "C" void test_parse_init_ack_resume_with_log()
{
	std::string sessionId = "00000000-0000-0000-0000-000000000000";
	std::string recordId = "11111111-1111-1111-1111-111111111111";
	const std::map<std::string, std::string> headers = {
		{JALN_HDRS_VERSION, JALN_VERSION},
		{JALN_HDRS_CONTENT_TYPE, JALN_STR_CT_JALOP},
		{JALN_HDRS_CONTENT_LENGTH, "0"},
		{JALN_HDRS_MESSAGE, JALN_MSG_INIT_ACK},
		{JALN_HDRS_SESSION_ID, sessionId},
		{JALN_HDRS_COMPRESSION, "None"},
		{JALN_HDRS_DIGEST, JAL_SHA256_ALGORITHM_URI},
		{JALN_HDRS_CONFIGURE_DIGEST_CHALLENGE, JALN_DIGEST_CHALLENGE_ON},
		{JALN_HDRS_ID, recordId},
		{JALN_HDRS_JOURNAL_OFFSET, "100"},
	};

	struct JalopResponse response;
	response.headers = headers;

	enum jaln_publish_mode mode = JALN_ARCHIVE_MODE;
	enum jaln_record_type type = JALN_RTYPE_LOG;

	try {
		assert_equals(ResponseType::InitAck, response.getResponseType());
		InitAck initAck(response,
			nominalAllowedDigestAlgs,
			nominalAllowedCompressions,
			nominalAllowedChallenge,
			mode,
			type);

		fprintf(stderr, "InitAck failed to throw with resume for log type\n");
		assert_true(false);
	} catch(std::exception& e) {
		assert_true(true);
	}
}

extern "C" void test_parse_init_ack_resume_with_audit()
{
	std::string sessionId = "00000000-0000-0000-0000-000000000000";
	std::string recordId = "11111111-1111-1111-1111-111111111111";
	const std::map<std::string, std::string> headers = {
		{JALN_HDRS_VERSION, JALN_VERSION},
		{JALN_HDRS_CONTENT_TYPE, JALN_STR_CT_JALOP},
		{JALN_HDRS_CONTENT_LENGTH, "0"},
		{JALN_HDRS_MESSAGE, JALN_MSG_INIT_ACK},
		{JALN_HDRS_SESSION_ID, sessionId},
		{JALN_HDRS_COMPRESSION, "None"},
		{JALN_HDRS_DIGEST, JAL_SHA256_ALGORITHM_URI},
		{JALN_HDRS_CONFIGURE_DIGEST_CHALLENGE, JALN_DIGEST_CHALLENGE_ON},
		{JALN_HDRS_ID, recordId},
		{JALN_HDRS_JOURNAL_OFFSET, "100"},
	};

	struct JalopResponse response;
	response.headers = headers;

	enum jaln_publish_mode mode = JALN_ARCHIVE_MODE;
	enum jaln_record_type type = JALN_RTYPE_AUDIT;

	try {
		assert_equals(ResponseType::InitAck, response.getResponseType());
		InitAck initAck(response,
			nominalAllowedDigestAlgs,
			nominalAllowedCompressions,
			nominalAllowedChallenge,
			mode,
			type);

		fprintf(stderr, "InitAck failed to throw with resume for log type\n");
		assert_true(false);
	} catch(std::exception& e) {
		assert_true(true);
	}
}

extern "C" void test_parse_init_nack_nominal()
{
	const std::map<std::string, std::string> headers = {
		{JALN_HDRS_CONTENT_TYPE, JALN_STR_CT_JALOP},
		{JALN_HDRS_CONTENT_LENGTH, "0"},
		{JALN_HDRS_MESSAGE, JALN_MSG_INIT_NACK},
		{JALN_HDRS_ERROR_MESSAGE, "JAL-Unsupported-Publisher-Id"},
	};

	struct JalopResponse response;
	response.headers = headers;

	try {
		assert_equals(ResponseType::InitNack, response.getResponseType());
		InitNack initNack(response);

		assert_equals(initNack.errors.size(), 1);
		assert_equals(initNack.errors[0], std::string("JAL-Unsupported-Publisher-Id"));
	} catch(std::exception& e) {
		fprintf(stderr, "Unexpected exception: %s\n", e.what());
		assert_true(false);
	}
}

extern "C" void test_parse_init_nack_nominal_multi()
{
	const std::map<std::string, std::string> headers = {
		{JALN_HDRS_CONTENT_TYPE, JALN_STR_CT_JALOP},
		{JALN_HDRS_CONTENT_LENGTH, "0"},
		{JALN_HDRS_MESSAGE, JALN_MSG_INIT_NACK},
		{JALN_HDRS_ERROR_MESSAGE, "JAL-Unsupported-Publisher-Id|JAL-Unsupported-Version"},
	};

	struct JalopResponse response;
	response.headers = headers;

	try {
		assert_equals(ResponseType::InitNack, response.getResponseType());
		InitNack initNack(response);

		assert_equals(initNack.errors.size(), 2);
		assert_equals(initNack.errors[0], std::string("JAL-Unsupported-Publisher-Id"));
		assert_equals(initNack.errors[1], std::string("JAL-Unsupported-Version"));
	} catch(std::exception& e) {
		fprintf(stderr, "Unexpected exception: %s\n", e.what());
		assert_true(false);
	}
}

extern "C" void test_parse_init_nack_with_content()
{
	const std::map<std::string, std::string> headers = {
		{JALN_HDRS_CONTENT_TYPE, JALN_STR_CT_JALOP},
		{JALN_HDRS_CONTENT_LENGTH, "123"},
		{JALN_HDRS_MESSAGE, JALN_MSG_INIT_NACK},
		{JALN_HDRS_ERROR_MESSAGE, "JAL-Unsupported-Publisher-Id"},
	};

	struct JalopResponse response;
	response.headers = headers;

	try {
		assert_equals(ResponseType::InitNack, response.getResponseType());
		InitNack initNack(response);

		fprintf(stderr, "InitNack constructor failed to throw with non-zero content length\n");
		assert_true(false);
	} catch(const InvalidResponse& e) {
		assert_true(true);
	}
}

extern "C" void test_parse_init_nack_missing_error_message()
{
	const std::map<std::string, std::string> headers = {
		{JALN_HDRS_CONTENT_TYPE, JALN_STR_CT_JALOP},
		{JALN_HDRS_CONTENT_LENGTH, "0"},
		{JALN_HDRS_MESSAGE, JALN_MSG_INIT_NACK},
	};

	struct JalopResponse response;
	response.headers = headers;

	try {
		assert_equals(ResponseType::InitNack, response.getResponseType());
		InitNack initNack(response);

		fprintf(stderr, "InitNack constructor failed to throw with missing error message\n");
		assert_true(false);
	} catch(const InvalidResponse& e) {
		assert_true(true);
	}
}

extern "C" void test_create_journal_missing_nominal()
{
	std::string sessionId = "00000000-0000-0000-000000000000";
	std::string recordId = "11111111-1111-1111-111111111111";
	try {
		JournalMissingMessage journalMissingMessage(
			sessionId,
			recordId);

		assert_equals(std::string(JALN_MSG_JOURNAL_MISSING), journalMissingMessage.headers.at(std::string(JALN_HDRS_MESSAGE)));
		assert_equals(sessionId, journalMissingMessage.headers.at(std::string(JALN_HDRS_SESSION_ID)));
		assert_equals(recordId, journalMissingMessage.headers.at(std::string(JALN_HDRS_ID)));
	} catch(const std::exception& e) {
		fprintf(stderr, "Unexpected exception: %s\n", e.what());
		assert_true(false);
	}
}

extern "C" void test_parse_journal_missing_response_nominal()
{
	const std::map<std::string, std::string> headers = {
		{JALN_HDRS_CONTENT_TYPE, JALN_STR_CT_JALOP},
		{JALN_HDRS_CONTENT_LENGTH, "0"},
		{JALN_HDRS_MESSAGE, JALN_MSG_JOURNAL_MISSING_RESPONSE},
	};

	struct JalopResponse response;
	response.headers = headers;

	try {
		assert_equals(ResponseType::JournalMissingResponse, response.getResponseType());
		JournalMissingResponse journalMissingResponse(response);
	} catch(std::exception& e) {
		fprintf(stderr, "Unexpected exception: %s\n", e.what());
		assert_true(false);
	}
}

extern "C" void test_parse_record_failure_nominal()
{
	std::string recordId = "00000000-0000-0000-0000-000000000000";
	std::string error = "JAL-Unsupported-Publisher-Id";
	const std::map<std::string, std::string> headers = {
		{JALN_HDRS_CONTENT_TYPE, JALN_STR_CT_JALOP},
		{JALN_HDRS_CONTENT_LENGTH, "0"},
		{JALN_HDRS_MESSAGE, JALN_MSG_RECORD_FAILURE},
		{JALN_HDRS_ID, recordId},
		{JALN_HDRS_ERROR_MESSAGE, error},
	};

	struct JalopResponse response;
	response.headers = headers;

	try {
		assert_equals(ResponseType::RecordFailure, response.getResponseType());
		RecordFailure recordFailure(response,
			recordId);

		assert_equals(recordId, recordFailure.id);
		assert_equals(1, recordFailure.errors.size());
		assert_equals(error, recordFailure.errors[0]);
	} catch(std::exception& e) {
		fprintf(stderr, "Unexpected exception: %s\n", e.what());
		assert_true(false);
	}
}

extern "C" void test_parse_session_failure_nominal()
{
	std::string recordId = "00000000-0000-0000-0000-000000000000";
	std::string error = "JAL-Unsupported-Session-Id";
	std::string sessionId = "11111111-1111-1111-1111-111111111111";
	const std::map<std::string, std::string> headers = {
		{JALN_HDRS_CONTENT_TYPE, JALN_STR_CT_JALOP},
		{JALN_HDRS_CONTENT_LENGTH, "0"},
		{JALN_HDRS_MESSAGE, JALN_MSG_SESSION_FAILURE},
		{JALN_HDRS_ID, recordId},
		{JALN_HDRS_SESSION_ID, sessionId},
		{JALN_HDRS_ERROR_MESSAGE, error},
	};

	struct JalopResponse response;
	response.headers = headers;

	try {
		assert_equals(ResponseType::SessionFailure, response.getResponseType());
		SessionFailure sessionFailure(response,
			recordId,
			sessionId);

		assert_equals(sessionId, sessionFailure.sessionId);
		assert_equals(recordId, sessionFailure.id);
		assert_equals(1, sessionFailure.errors.size());
		assert_equals(error, sessionFailure.errors[0]);
	} catch(std::exception& e) {
		fprintf(stderr, "Unexpected exception: %s\n", e.what());
		assert_true(false);
	}
}

// Using RecordFailure to test the no-directly-observable split_errors method
// since it's the simplest
extern "C" void test_parse_split_errors_empty()
{
	std::string recordId = "00000000-0000-0000-0000-000000000000";
	const std::map<std::string, std::string> headers = {
		{JALN_HDRS_CONTENT_TYPE, JALN_STR_CT_JALOP},
		{JALN_HDRS_CONTENT_LENGTH, "0"},
		{JALN_HDRS_MESSAGE, JALN_MSG_RECORD_FAILURE},
		{JALN_HDRS_ID, recordId},
		{JALN_HDRS_ERROR_MESSAGE, ""},
	};

	struct JalopResponse response;
	response.headers = headers;

	try {
		assert_equals(ResponseType::RecordFailure, response.getResponseType());
		RecordFailure recordFailure(response, recordId);

		// Empty error messages are not allowed
		assert_true(false);
	} catch(const InvalidResponse& e) {
		assert_true(true);
	}
}

// Using RecordFailure to test the no-directly-observable split_errors method
// since it's the simplest
extern "C" void test_parse_split_errors_only_bar()
{
	std::string recordId = "00000000-0000-0000-0000-000000000000";
	const std::map<std::string, std::string> headers = {
		{JALN_HDRS_CONTENT_TYPE, JALN_STR_CT_JALOP},
		{JALN_HDRS_CONTENT_LENGTH, "0"},
		{JALN_HDRS_MESSAGE, JALN_MSG_RECORD_FAILURE},
		{JALN_HDRS_ID, recordId},
		{JALN_HDRS_ERROR_MESSAGE, "|"},
	};

	struct JalopResponse response;
	response.headers = headers;

	try {
		assert_equals(ResponseType::RecordFailure, response.getResponseType());
		RecordFailure recordFailure(response, recordId);

		// Empty error messages are not allowed
		assert_true(false);
	} catch(const InvalidResponse& e) {
		assert_true(true);
	}
}

// Using RecordFailure to test the no-directly-observable split_errors method
// since it's the simplest
extern "C" void test_parse_split_errors_ignore_leading_bar()
{
	std::string recordId = "00000000-0000-0000-0000-000000000000";
	const std::map<std::string, std::string> headers = {
		{JALN_HDRS_CONTENT_TYPE, JALN_STR_CT_JALOP},
		{JALN_HDRS_CONTENT_LENGTH, "0"},
		{JALN_HDRS_MESSAGE, JALN_MSG_RECORD_FAILURE},
		{JALN_HDRS_ID, recordId},
		{JALN_HDRS_ERROR_MESSAGE, "|JAL-Invalid-Jal-Id"},
	};

	struct JalopResponse response;
	response.headers = headers;

	try {
		assert_equals(ResponseType::RecordFailure, response.getResponseType());
		RecordFailure recordFailure(response, recordId);

		assert_equals(recordFailure.errors.size(), 1);
		assert_equals(recordFailure.errors[0], std::string("JAL-Invalid-Jal-Id"));

		// Empty error messages are not allowed
	} catch(const std::exception& e) {
		fprintf(stderr, "Unexpected exception: %s\n", e.what());
		assert_true(false);
	}
}

// Using RecordFailure to test the no-directly-observable split_errors method
// since it's the simplest
extern "C" void test_parse_split_errors_ignore_leading_double_bar()
{
	std::string recordId = "00000000-0000-0000-0000-000000000000";
	const std::map<std::string, std::string> headers = {
		{JALN_HDRS_CONTENT_TYPE, JALN_STR_CT_JALOP},
		{JALN_HDRS_CONTENT_LENGTH, "0"},
		{JALN_HDRS_MESSAGE, JALN_MSG_RECORD_FAILURE},
		{JALN_HDRS_ID, recordId},
		{JALN_HDRS_ERROR_MESSAGE, "||JAL-Invalid-Jal-Id"},
	};

	struct JalopResponse response;
	response.headers = headers;

	try {
		assert_equals(ResponseType::RecordFailure, response.getResponseType());
		RecordFailure recordFailure(response, recordId);

		assert_equals(recordFailure.errors.size(), 1);
		assert_equals(recordFailure.errors[0], std::string("JAL-Invalid-Jal-Id"));

		// Empty error messages are not allowed
	} catch(const std::exception& e) {
		fprintf(stderr, "Unexpected exception: %s\n", e.what());
		assert_true(false);
	}
}

// Using RecordFailure to test the no-directly-observable split_errors method
// since it's the simplest
extern "C" void test_parse_split_errors_ignore_trailing_bar()
{
	std::string recordId = "00000000-0000-0000-0000-000000000000";
	const std::map<std::string, std::string> headers = {
		{JALN_HDRS_CONTENT_TYPE, JALN_STR_CT_JALOP},
		{JALN_HDRS_CONTENT_LENGTH, "0"},
		{JALN_HDRS_MESSAGE, JALN_MSG_RECORD_FAILURE},
		{JALN_HDRS_ID, recordId},
		{JALN_HDRS_ERROR_MESSAGE, "JAL-Invalid-Jal-Id|"},
	};

	struct JalopResponse response;
	response.headers = headers;

	try {
		assert_equals(ResponseType::RecordFailure, response.getResponseType());
		RecordFailure recordFailure(response, recordId);

		assert_equals(recordFailure.errors.size(), 1);
		assert_equals(recordFailure.errors[0], std::string("JAL-Invalid-Jal-Id"));

		// Empty error messages are not allowed
	} catch(const std::exception& e) {
		fprintf(stderr, "Unexpected exception: %s\n", e.what());
		assert_true(false);
	}
}

// Using RecordFailure to test the no-directly-observable split_errors method
// since it's the simplest
extern "C" void test_parse_split_errors_ignore_trailing_double_bar()
{
	std::string recordId = "00000000-0000-0000-0000-000000000000";
	const std::map<std::string, std::string> headers = {
		{JALN_HDRS_CONTENT_TYPE, JALN_STR_CT_JALOP},
		{JALN_HDRS_CONTENT_LENGTH, "0"},
		{JALN_HDRS_MESSAGE, JALN_MSG_RECORD_FAILURE},
		{JALN_HDRS_ID, recordId},
		{JALN_HDRS_ERROR_MESSAGE, "JAL-Invalid-Jal-Id||"},
	};

	struct JalopResponse response;
	response.headers = headers;

	try {
		assert_equals(ResponseType::RecordFailure, response.getResponseType());
		RecordFailure recordFailure(response, recordId);

		assert_equals(recordFailure.errors.size(), 1);
		assert_equals(recordFailure.errors[0], std::string("JAL-Invalid-Jal-Id"));

		// Empty error messages are not allowed
	} catch(const std::exception& e) {
		fprintf(stderr, "Unexpected exception: %s\n", e.what());
		assert_true(false);
	}
}

// Using RecordFailure to test the no-directly-observable split_errors method
// since it's the simplest
extern "C" void test_parse_split_errors_single_bar_separator()
{
	std::string recordId = "00000000-0000-0000-0000-000000000000";
	const std::map<std::string, std::string> headers = {
		{JALN_HDRS_CONTENT_TYPE, JALN_STR_CT_JALOP},
		{JALN_HDRS_CONTENT_LENGTH, "0"},
		{JALN_HDRS_MESSAGE, JALN_MSG_RECORD_FAILURE},
		{JALN_HDRS_ID, recordId},
		{JALN_HDRS_ERROR_MESSAGE, "JAL-Invalid-Jal-Id|JAL-Invalid-Log-Length"},
	};

	struct JalopResponse response;
	response.headers = headers;

	try {
		assert_equals(ResponseType::RecordFailure, response.getResponseType());
		RecordFailure recordFailure(response, recordId);

		assert_equals(recordFailure.errors.size(), 2);
		assert_equals(recordFailure.errors[0], std::string("JAL-Invalid-Jal-Id"));
		assert_equals(recordFailure.errors[1], std::string("JAL-Invalid-Log-Length"));

		// Empty error messages are not allowed
	} catch(const std::exception& e) {
		fprintf(stderr, "Unexpected exception: %s\n", e.what());
		assert_true(false);
	}
}

// Using RecordFailure to test the no-directly-observable split_errors method
// since it's the simplest
extern "C" void test_parse_split_errors_double_bar_separator()
{
	std::string recordId = "00000000-0000-0000-0000-000000000000";
	const std::map<std::string, std::string> headers = {
		{JALN_HDRS_CONTENT_TYPE, JALN_STR_CT_JALOP},
		{JALN_HDRS_CONTENT_LENGTH, "0"},
		{JALN_HDRS_MESSAGE, JALN_MSG_RECORD_FAILURE},
		{JALN_HDRS_ID, recordId},
		{JALN_HDRS_ERROR_MESSAGE, "JAL-Invalid-Jal-Id||JAL-Invalid-Log-Length"},
	};

	struct JalopResponse response;
	response.headers = headers;

	try {
		assert_equals(ResponseType::RecordFailure, response.getResponseType());
		RecordFailure recordFailure(response, recordId);

		assert_equals(recordFailure.errors.size(), 2);
		assert_equals(recordFailure.errors[0], std::string("JAL-Invalid-Jal-Id"));
		assert_equals(recordFailure.errors[1], std::string("JAL-Invalid-Log-Length"));

		// Empty error messages are not allowed
	} catch(const std::exception& e) {
		fprintf(stderr, "Unexpected exception: %s\n", e.what());
		assert_true(false);
	}
}

// Using RecordFailure to test the no-directly-observable split_errors method
// since it's the simplest
extern "C" void test_parse_split_errors_way_too_many_bars()
{
	std::string recordId = "00000000-0000-0000-0000-000000000000";
	const std::map<std::string, std::string> headers = {
		{JALN_HDRS_CONTENT_TYPE, JALN_STR_CT_JALOP},
		{JALN_HDRS_CONTENT_LENGTH, "0"},
		{JALN_HDRS_MESSAGE, JALN_MSG_RECORD_FAILURE},
		{JALN_HDRS_ID, recordId},
		{JALN_HDRS_ERROR_MESSAGE, "|||JAL-Invalid-Jal-Id|||JAL-Invalid-Log-Length|||"},
	};

	struct JalopResponse response;
	response.headers = headers;

	try {
		assert_equals(ResponseType::RecordFailure, response.getResponseType());
		RecordFailure recordFailure(response, recordId);

		assert_equals(recordFailure.errors.size(), 2);
		assert_equals(recordFailure.errors[0], std::string("JAL-Invalid-Jal-Id"));
		assert_equals(recordFailure.errors[1], std::string("JAL-Invalid-Log-Length"));

		// Empty error messages are not allowed
	} catch(const std::exception& e) {
		fprintf(stderr, "Unexpected exception: %s\n", e.what());
		assert_true(false);
	}
}

// Test all nominal values for the close session message
extern "C" void test_create_close_session()
{
	std::string sessionId = "00000000-0000-0000-0000-000000000000";
	try {
		CloseSessionMessage closeSessionMessage(sessionId);

		assert_equals(std::string(JALN_MSG_CLOSE_SESSION), closeSessionMessage.headers.at(std::string(JALN_HDRS_MESSAGE)));
		assert_equals(sessionId, closeSessionMessage.headers.at(std::string(JALN_HDRS_SESSION_ID)));

	} catch(const std::exception& e) {
		// Success if the test doesn't throw
		fprintf(stderr, "Unexpected exception: %s\n", e.what());
		assert_true(false);
	}
}

extern "C" void test_parse_close_session_reponse()
{
	const std::map<std::string, std::string> headers = {
		{JALN_HDRS_CONTENT_TYPE, JALN_STR_CT_JALOP},
		{JALN_HDRS_CONTENT_LENGTH, "0"},
		{JALN_HDRS_MESSAGE, JALN_MSG_CLOSE_SESSION_RESPONSE},
	};

	struct JalopResponse response;
	response.headers = headers;

	try {
		assert_equals(ResponseType::CloseSessionResponse, response.getResponseType());
		CloseSessionResponse closeSessionResponse(response);

	} catch(std::exception& e) {
		fprintf(stderr, "Unexpected exception: %s\n", e.what());
		assert_true(false);
	}
}
