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

#if !defined(_EAP_MEMORY_H_)
#define _EAP_MEMORY_H_


#if !defined(USE_EAP_MEMORY_FUNCTIONS_FAILURES)

	#define g_eap_set_memory_parameters( \
		alloc_failures_probability, \
		alloc_failures_skip_count)

	#define g_eap_alloc_failures_enabled()

	#define g_eap_alloc_failures_disabled()

#endif // #if defined(USE_EAP_MEMORY_FUNCTIONS_FAILURES)


#if defined(DMALLOC) || defined(USE_EAP_MEMORY_FUNCTIONS)

	#include "eap_tools.h"
	#include "eap_variable_data.h"
	#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_AM_MEMORY_H)
	#define EAP_CLASS_VISIBILITY_EAP_AM_MEMORY_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_AM_MEMORY_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_MEMORY_H 
	#define EAP_FUNC_EXPORT_EAP_AM_MEMORY_H 
	#define EAP_C_FUNC_EXPORT_EAP_AM_MEMORY_H 
#elif defined(EAP_EXPORT_EAP_AM_MEMORY_H)
	#define EAP_CLASS_VISIBILITY_EAP_AM_MEMORY_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_AM_MEMORY_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_MEMORY_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_AM_MEMORY_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_AM_MEMORY_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_AM_MEMORY_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_AM_MEMORY_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_MEMORY_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_AM_MEMORY_H 
	#define EAP_C_FUNC_EXPORT_EAP_AM_MEMORY_H 
#endif
// End: added by script change_export_macros.sh.


	#if defined(USE_EAP_MEMORY_FUNCTIONS_FAILURES)

		void g_eap_set_memory_parameters(
			const u32_t alloc_failures_probability,
			const u32_t alloc_failures_skip_count);

		void g_eap_alloc_failures_enabled();

		void g_eap_alloc_failures_disabled();

		bool g_eap_alloc_failures_active();

	#endif // #if defined(USE_EAP_MEMORY_FUNCTIONS_FAILURES)


	#define USE_JPH_REALLOC

	#if defined(__GNUC__)
		#include <unistd.h>
	#elif defined(__SYMBIAN32__)
		#include <e32std.h>
	#endif

	#if defined(_WIN32) && !defined(__GNUC__) && defined(USE_MEMORY_LEAK_DETECTION)
		#pragma message("Uses memory leak detection of WIN32.") 
		#define _CRTDBG_MAP_ALLOC
		#include <crtdbg.h>
	#endif

	#if defined(_WIN32) || defined(__GNUC__)
		#include <stdlib.h>
	#endif

	#if defined(__cplusplus) || defined(__cc)
	extern "C" {
	#endif

	#if defined(_WIN32)	|| defined(__GNUC__)
		/*
		 * An overload function the malloc.
		 */
		EAP_C_FUNC_VISIBILITY_EAP_AM_MEMORY_H void *jph_malloc(size_t n);

		/*
		 * An overload function the malloc.
		 */
		EAP_C_FUNC_VISIBILITY_EAP_AM_MEMORY_H void *jph_malloc_ex(size_t n, const char *file, int line);

		#if defined(USE_JPH_REALLOC)
			/*
			 * An overload function the realloc.
			 */
			EAP_C_FUNC_VISIBILITY_EAP_AM_MEMORY_H void *jph_realloc(void *oldbuf, size_t n);

			/*
			 * An overload function the realloc.
			 */
			EAP_C_FUNC_VISIBILITY_EAP_AM_MEMORY_H void *jph_realloc_ex(void *oldbuf, size_t n, const char *file, int line);
		#endif //#if defined(USE_JPH_REALLOC)

		#if defined(USE_JPH_CALLOC)
			/*
			 * An overload function the calloc.
			 */
			EAP_C_FUNC_VISIBILITY_EAP_AM_MEMORY_H void *jph_calloc(size_t count, size_t size);
		#endif //#if defined(USE_JPH_CALLOC)

		/*
		 * An overload function for the free.
		 */
		EAP_C_FUNC_VISIBILITY_EAP_AM_MEMORY_H void jph_free(void *cp);


		EAP_C_FUNC_VISIBILITY_EAP_AM_MEMORY_H void *jph_new(size_t n);

		EAP_C_FUNC_VISIBILITY_EAP_AM_MEMORY_H void jph_delete(void *cp);

	#endif /* #if defined(_WIN32) */

	#if defined(__cplusplus) || defined(__cc)
	}
	#endif


	#if defined(__cplusplus) || defined(__cc)

		// NOTE, gcc does not need these prototypes. These are defined internally.

		#if defined(_WIN32) && !defined(__GNUC__) && !defined(__SYMBIAN32__) && !defined(USE_MEMORY_LEAK_DETECTION)

			inline void *operator new(size_t n)
			{
				return jph_new(n);
			}

			inline void *operator new[](size_t n)
			{
				return jph_new(n);
			}

			inline void operator delete(void *cp)
			{
				if (cp)
				{
					jph_delete(cp);
				}
			}

			inline void operator delete[](void *cp)
			{
				if (cp)
				{
					jph_delete(cp);
				}
			}

		#elif defined(__GNUC__)

			#include <new>

			void *operator new(std::size_t n) throw (std::bad_alloc);

			void *operator new[](std::size_t n) throw (std::bad_alloc);

			void operator delete(void *cp) throw();

			void operator delete[](void *cp) throw();

		#endif //#if defined(WIN32)


		#if defined(unix)
			typedef int (*jph_new_handler) (size_t);
			EAP_C_FUNC_VISIBILITY_EAP_AM_MEMORY_H jph_new_handler jph_set_new_handler(jph_new_handler);
		#elif defined(_WIN32) && !defined(__GNUC__)
			typedef int (__cdecl * jph_new_handler) (size_t);
			EAP_C_FUNC_VISIBILITY_EAP_AM_MEMORY_H jph_new_handler __cdecl jph_set_new_handler(jph_new_handler);
		#else
			// Not supported in Symbian.
		#endif


	#endif // #if defined(__cplusplus) || defined(__cc)

#elif defined(USE_EAP_GLOBAL_NEW_AND_DELETE_H)

	#include "GlobalNewAndDelete.h"

#endif //#if defined(DMALLOC) || defined(USE_EAP_MEMORY_FUNCTIONS)

#endif //#if !defined(_EAP_MEMORY_H_)

//--------------------------------------------------



// End.
