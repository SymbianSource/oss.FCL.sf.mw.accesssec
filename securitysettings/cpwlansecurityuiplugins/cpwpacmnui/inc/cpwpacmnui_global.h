/*
 * Copyright (c) 2010 Nokia Corporation and/or its subsidiary(-ies).
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
 * Description: 
 *    
 *
 */

/*
 * %version: 5 %
 */
#ifndef CPWPACMNUI_GLOBAL_H_
#define CPWPACMNUI_GLOBAL_H_


#include <QtCore/QtGlobal>
 
 #if defined(WPAUI_LIBRARY)
 #define WPAUI_EXPORT Q_DECL_EXPORT
 #else
 #if defined(WPAUI_NO_LIBRARY)
 #define WPAUI_EXPORT
 #else
 #define WPAUI_EXPORT Q_DECL_IMPORT
 #endif
 #endif


#endif //CPWPACMNUI_GLOBAL_H_
