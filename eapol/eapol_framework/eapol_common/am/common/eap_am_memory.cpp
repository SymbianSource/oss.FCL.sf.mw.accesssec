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
	#define EAP_FILE_NUMBER_ENUM 9 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#include "eap_variable_data.h"
#include "eap_am_export.h"
#include "abs_eap_am_tools.h"
#include "eap_am_memory.h"

#if defined(DMALLOC)
	//#pragma message("Uses dmalloc.") 
	#include <dmalloc.h>
#endif // #if defined(DMALLOC)

#if defined(DMALLOC) || defined(USE_EAP_MEMORY_FUNCTIONS)

#if (defined(_WIN32) || defined(__GNUC__)) && !defined(__SYMBIAN32__)

	static jph_new_handler g_jph_new_handler = NULL;

	#if defined(USE_EAP_MEMORY_FUNCTIONS_FAILURES)

		#include <time.h>
		bool g_eap_alloc_failures_enabled_flag = false;
		u32_t g_eap_alloc_failures_probability = 0ul;
		u32_t g_eap_alloc_failures_skip_count = 0ul;
		u32_t g_eap_alloc_failures_skip_counter_value = 0ul;

		const u32_t g_eap_alloc_max_probapility = 4294967295ul;

		void g_eap_set_memory_parameters(
			const u32_t alloc_failures_probability,
			const u32_t alloc_failures_skip_count)
		{
			srand(time(0));

			g_eap_alloc_failures_enabled_flag = true;

			g_eap_alloc_failures_probability = alloc_failures_probability;

			g_eap_alloc_failures_skip_count = alloc_failures_skip_count;

			g_eap_alloc_failures_skip_counter_value = 0ul;
		}

		void g_eap_alloc_failures_enabled()
		{
			if (g_eap_alloc_failures_probability != 0)
			{
				// Parameters must be set before failures can be enabled.
				g_eap_alloc_failures_enabled_flag = true;
			}
		}

		void g_eap_alloc_failures_disabled()
		{
			g_eap_alloc_failures_enabled_flag = false;
		}

		bool g_eap_alloc_failures_active()
		{
			return (g_eap_alloc_failures_skip_counter_value >= g_eap_alloc_failures_skip_count
				&& g_eap_alloc_failures_probability == g_eap_alloc_max_probapility);
		}

		static bool g_eap_memory_randomize_error()
		{
			// We cannot use abs_eap_am_tools_c here.

			if (g_eap_alloc_failures_enabled_flag == false)
			{
				return false;
			}

			if (g_eap_alloc_failures_skip_counter_value < g_eap_alloc_failures_skip_count)
			{
				++g_eap_alloc_failures_skip_counter_value;
				return false;
			}

			u32_t random_guard = static_cast<u32_t>(rand());
			if (random_guard < g_eap_alloc_failures_probability)
			{
				return true;
			}
			else
			{
				return false;
			}
		}
	#endif //#if defined(USE_EAP_MEMORY_FUNCTIONS_FAILURES)

#else
	// Note Symbian does not support global writable data in DLL.
#endif //#if defined(_WIN32) || defined(__GNUC__)


#if defined(_WIN32) || defined(__GNUC__)
/*
 * An overload function the malloc.
 */
EAP_C_FUNC_EXPORT void *jph_malloc(size_t n)
{

#if defined(USE_EAP_MEMORY_FUNCTIONS_FAILURES)
	if (g_eap_memory_randomize_error() == true)
	{
		// This is failed allocation.
		return 0;
	}
#endif //#if defined(USE_EAP_MEMORY_FUNCTIONS_FAILURES)

	#if defined(__SYMBIAN32__)
		return User::Alloc(n);
	#else
		return malloc(n);
	#endif
}

/*
 * An overload function the malloc.
 */
EAP_C_FUNC_EXPORT void *jph_malloc_ex(size_t n, const char *file, int line)
{
	return jph_malloc(n);
}
#endif //#if defined(_WIN32) || defined(__GNUC__)


#if defined(_WIN32) || defined(__GNUC__)
	#if defined(USE_JPH_REALLOC)
	/*
	 * An overload function the realloc.
	 */
	EAP_C_FUNC_EXPORT void *jph_realloc(void *oldbuf, size_t n)
	{
		return realloc(oldbuf,n);
	}

	/*
	 * An overload function the realloc.
	 */
	EAP_C_FUNC_EXPORT void *jph_realloc_ex(void *oldbuf, size_t n, const char *file, int line)
	{
		return jph_realloc(oldbuf,n);
	}
	#endif //#if defined(USE_JPH_REALLOC)


	#if defined(USE_JPH_CALLOC)
	/*
	 * An overload function the jph_calloc.
	 */
	EAP_C_FUNC_EXPORT void *jph_calloc(size_t count, size_t size)
	{
		return calloc(count,size);
	}
	#endif //#if defined(USE_JPH_CALLOC)


	/*
	 * An overload function for the free.
	 */
	EAP_C_FUNC_EXPORT void jph_free(void *cp)
	{
		#if defined(__SYMBIAN32__)
			User::Free(cp);
		#else
			free( cp );
		#endif
	}


	EAP_C_FUNC_EXPORT void *jph_new(size_t n)
	{
		void *mem = jph_malloc(n);

	#if (defined(_WIN32) || defined(__GNUC__)) && !defined(__SYMBIAN32__)
		if (!mem && g_jph_new_handler)
		{
			if (g_jph_new_handler(n))
			{
				mem = jph_malloc(n);
			}
		}
	#endif //#if (defined(_WIN32) || defined(__GNUC__)) && !defined(__SYMBIAN32__)

		return mem;
	}

	EAP_C_FUNC_EXPORT void jph_delete(void *cp)
	{
		jph_free( cp );
	}

#endif /* #if defined(_WIN32) */


#if defined(_WIN32) && defined(__GNUC__)


/* This will be __builtin_new. */
EAP_C_FUNC_EXPORT void *operator new(size_t n)
{
	return jph_new(n);
}

/* This will be __builtin_vec_new. */
EAP_C_FUNC_EXPORT void *operator new[](size_t n)
{
	return jph_new(n);
}

/* This will be __builtin_delete. */
EAP_C_FUNC_EXPORT void operator delete(void *cp)
{
	if (cp)
	{
		jph_delete(cp);
	}
}

/* This will be __builtin_vec_delete. */
EAP_C_FUNC_EXPORT void operator delete[](void *cp)
{
	if (cp)
	{
		jph_delete(cp);
	}
}

#endif /* #if defined(_WIN32) */


#if !defined(_WIN32) && defined(__GNUC__)

EAP_C_FUNC_EXPORT void *operator new(std::size_t n) throw (std::bad_alloc)
{
	return jph_new(n);
}

EAP_C_FUNC_EXPORT void *operator new[](std::size_t n) throw (std::bad_alloc)
{
	return jph_new(n);
}

EAP_C_FUNC_EXPORT void operator delete(void *cp) throw()
{
	if (cp)
	{
		jph_delete(cp);
	}
}

EAP_C_FUNC_EXPORT void operator delete[](void *cp) throw()
{
	if (cp)
	{
		jph_delete(cp);
	}
}

#endif


#if (defined(_WIN32) || defined(__GNUC__)) && !defined(__SYMBIAN32__)
EAP_C_FUNC_EXPORT jph_new_handler jph_set_new_handler(jph_new_handler handler)
{
	jph_new_handler oldhandler = g_jph_new_handler;
	g_jph_new_handler = handler;
	return oldhandler;
}
#endif //#if defined(_WIN32) || defined(__GNUC__)

#endif //#if defined(DMALLOC) || defined(USE_EAP_MEMORY_FUNCTIONS)




// End.
