/*
* Copyright (c) 2001-2005 Nokia Corporation and/or its subsidiary(-ies).
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




#if !defined( _EAP_AM_TRACE_SYMBIAN_H_ )
#define _EAP_AM_TRACE_SYMBIAN_H_

#if defined(_DEBUG)

#include "eap_status_string.h"
#include <e32debug.h>

#define DEBUG(a)		            RDebug::Print(_L(a))
#define DEBUG1(a,b)		            RDebug::Print(_L(a),b)
#define DEBUG2(a,b,c)	            RDebug::Print(_L(a),b,c)
#define DEBUG3(a,b,c,d)	            RDebug::Print(_L(a),b,c,d)
#define DEBUG4(a,b,c,d,e)	        RDebug::Print(_L(a),b,c,d,e)
#define DEBUG5(a,b,c,d,e,f)	        RDebug::Print(_L(a),b,c,d,e,f)
#define DEBUG6(a,b,c,d,e,f,g)	    RDebug::Print(_L(a),b,c,d,e,f,g)
#define DEBUG7(a,b,c,d,e,f,g,h) 	RDebug::Print(_L(a),b,c,d,e,f,g,h)
#define DEBUG8(a,b,c,d,e,f,g,h,i)	RDebug::Print(_L(a),b,c,d,e,f,g,h,i)

void trace_data(
	eap_const_string prefix,
	const void * const p_data,
	const u32_t data_length);

#define EAP_TRACE_DEBUG_SYMBIAN(_parameter_list_) \
		{ \
			RDebug::Print _parameter_list_ ; \
		} \

#define EAP_TRACE_DATA_DEBUG_SYMBIAN(_parameter_list_) \
		{ \
			trace_data _parameter_list_ ; \
		} \

#else // #if defined(_DEBUG) || defined(DEBUG)

#define DEBUG(a)
#define DEBUG1(a,b)
#define DEBUG2(a,b,c)
#define DEBUG3(a,b,c,d)
#define DEBUG4(a,b,c,d,e)
#define DEBUG5(a,b,c,d,e,f)
#define DEBUG6(a,b,c,d,e,f,g)
#define DEBUG7(a,b,c,d,e,f,g,h)
#define DEBUG8(a,b,c,d,e,f,g,h,i)

#define EAP_TRACE_DEBUG_SYMBIAN(_parameter_list_) 

#define EAP_TRACE_DATA_DEBUG_SYMBIAN(_parameter_list_)

#endif // #if defined(_DEBUG) || defined(DEBUG)

#endif //#if !defined( _EAP_AM_TRACE_SYMBIAN_H_ )
