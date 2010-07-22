/*
* Copyright (c) 2001-2006 Nokia Corporation and/or its subsidiary(-ies).
* All rights reserved.
* This component and the accompanying materials are made available
* under the terms of the License "Eclipse Public License v1.0"
* which accompanies this distribution, and is available
* at the URL "http://www.eclipse.org/legal/epl-v10.html".
*
* Initial Contributors:
* Nokia Corporation - initial contribution.
*
* Contributors:
*
* Description:  EAP and WLAN authentication protocols.
*
*/

/*
* %version: %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 16 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)


#include "eap_am_memory.h"
#include "fileconfig_utils.h"

#include <stdlib.h>

static char* get_subsect (FILE* file)
{

	char* result = NULL;
	char* line = new char[MAX_LINE_LENGTH];

	if(!line) {
		return NULL;
	}
	
	for(;;)
	{
		result = fgets(line, MAX_LINE_LENGTH, file);
		
		// error or end of file
		if(!result)
		{
			delete[] line;
			break;
		}
		
		// too short line, ignore
		if(strlen(result) < 2)
		{
			continue;
		}
		
		// In Linux and Symbian we have to remove
		// the MS-DOS style carriage return
		// (if the conf file happens to include those CRs).
		if(result[strlen(result) - 2] == 0x0d)
		{
			result[strlen(result) - 2] = 0x0a;
			result[strlen(result) - 1] = 0x00;
		}
		
		// ignore the lines starting with newline, space, tab or '#'
		if ((*result == '\n') ||
			(*result == ' ') ||
			(*result == '\t') ||
			(*result == '#'))
		{
			continue;
		}
		else
		{
			break;
		}
	}

	return result;
}

static int is_sect (char* line, char const* sectname)
{
	size_t length;
	
	if (strlen (line) < (length = strlen (sectname))){
		return 0;
	}
	
	return strncmp (sectname, line, length) == 0;
}

void cnf_subsects (FILE* file, const SubSection* subsects, void* data)
{
	const SubSection* iter;
	char* line;
	int found;
	
	for (line = get_subsect (file); line; line = get_subsect (file))
	{
		for (found = 0, iter = subsects; iter->name; iter++)
		{
			if (is_sect (line, iter->name))
			{
				line [strlen (line) - 1] = '\0';
				(*iter->handler) (line, data);
				found = 1;
				break;
			}
		}
		if (!found)
		{
			printf("ERROR: unrecognized subsection: %s\n", line);
		}
		delete[] line;
	}
}


static char* find_rvalue (char* param)
{
	char* rvalue;
	
	for (rvalue = param; *rvalue; rvalue++)
	{
		if (*rvalue == '=')
		{
			break;
		}
	}
	
	if (!*rvalue)
	{
		return NULL;
	}

	// Check are there defined environment variable to override the file confoguration.
	{
		// backup spaces.
		char *param_end = rvalue;
		for (param_end--; isspace(*param_end); param_end--){
			/* empty */
		}
		param_end++;
		char saved_char = *param_end;
		*param_end = '\0';
		char * env_value = getenv(param);
		if (env_value != 0)
		{
			printf("%s=%s; from environment variable\n", param, env_value);
		}
		*param_end = saved_char;

		if (env_value != 0)
		{
			// There is overriding environment variable.
			return env_value;
		}
	}

	
	for (rvalue++; isspace(*rvalue); rvalue++){
		/* empty */
	}
	
	printf("%s\n", param);
	return rvalue;
}

void cnf_get_string (char* target, char* param, size_t maxlen)
{
	size_t len;
	
	// Returned value could be pointer to environment value.
	// Do not modify returned value.
	param = find_rvalue (param);
	
	if (param == 0
		|| target == 0)
	{
		return;
	}
	
	len = min (maxlen - 1, strlen (param));
	memcpy (target, param, len);
	target[len] = '\0';
}

i32_t cnf_get_int32 (char* param)
{
	param = find_rvalue (param);
	
	if (!param)
	{
		return 0;
	}
	
	return atol (param);
}
