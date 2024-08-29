#include <exception>
#include <string>

#include <jal_seccomp_enforcer.h>
#include <jal_seccomp_enforcer.hpp>

struct jal_seccomp_enforcer_t* jal_seccomp_enforcer_create(
	char* configFile)
{
	if(NULL == configFile)
	{
		fprintf(stderr, "Error: NULL config_path in jal_seccomp_enforcer_create\n");
		return NULL;
	}

	JalSeccompEnforcer* enforcer;
	try
	{
		enforcer = new JalSeccompEnforcer(std::string(configFile));
	}
	catch(std::exception& e)
	{
		fprintf(stderr,
			"Error: Failed to create jal_seccomp_enforcer with reason: %s\n",
			e.what());
		return NULL;
	}
	return reinterpret_cast<struct jal_seccomp_enforcer_t*>(enforcer);
}

void jal_seccomp_enforcer_destroy(
	struct jal_seccomp_enforcer_t** enforcer)
{
	if(NULL == enforcer)
	{
		return;
	}
	delete reinterpret_cast<JalSeccompEnforcer*>(*enforcer);
	*enforcer = NULL;
}

int jal_seccomp_enforcer_apply_initial(
	struct jal_seccomp_enforcer_t* enforcer)
{
	if(NULL == enforcer)
	{
		fprintf(stderr, "Error: NULL enforcer in jal_seccomp_enforcer_apply_initial\n");
		return -1;
	}

	JalSeccompEnforcer* jalSeccompEnforcer = reinterpret_cast<JalSeccompEnforcer*>(enforcer);
	if(NULL == jalSeccompEnforcer)
	{
		fprintf(stderr, "Error: Unable to interpret pointer as JalSeccompEnforcer in"
			" jal_seccomp_enforcer_apply_initial\n");
		return -1;
	}

	try
	{
		jalSeccompEnforcer->applyInitial();
	}
	catch(std::exception &e)
	{
		fprintf(stderr,
			"Error: Unable to apply initial seccomp rules with reason: %s\n",
			e.what());
		return -1;
	}
	return 0;
}

int jal_seccomp_enforcer_apply_final(
	struct jal_seccomp_enforcer_t* enforcer)
{
	if(NULL == enforcer)
	{
		fprintf(stderr, "Error: NULL enforcer in jal_seccomp_enforcer_apply_final\n");
		return -1;
	}

	JalSeccompEnforcer* jalSeccompEnforcer = reinterpret_cast<JalSeccompEnforcer*>(enforcer);
	if(NULL == jalSeccompEnforcer)
	{
		fprintf(stderr, "Error: Unable to interpret pointer as JalSeccompEnforcer in"
			" jal_seccomp_enforcer_apply_final\n");
		return -1;
	}

	try
	{
		jalSeccompEnforcer->applyFinal();
	}
	catch(std::exception &e)
	{
		fprintf(stderr,
			"Error: Unable to apply initial seccomp rules with reason: %s\n",
			e.what());
		return -1;
	}
	return 0;
}
