/*
 * Copyright (c) 2010 Nokia Corporation and/or its subsidiary(-ies).
 * All rights reserved.
 * This component and the accompanying materials are made available
 * under the terms of "Eclipse Public License v1.0"
 * which accompanies this distribution, and is available
 * at the URL "http://www.eclipse.org/legal/epl-v10.html".
 *
 * Initial Contributors:
 * Nokia Corporation - initial contribution.
 *
 * Contributors:
 *
 * Description: 
 *   Control Panel EAP plugin information
 *
 */

/*
 * %version: 3 %
 */


#ifndef EAPQTPLUGINHANDLE_P_H
#define EAPQTPLUGINHANDLE_P_H

// System includes
#include <eapqtexpandedeaptype.h>

// User includes

// Forward declarations

// External data types

// Constants

// Class declaration
class EapQtPluginHandlePrivate
{

public:

    // Data types

    EapQtPluginHandlePrivate(const EapQtExpandedEapType& type, const int uid);
    ~EapQtPluginHandlePrivate();

private:

    EapQtPluginHandlePrivate();
    Q_DISABLE_COPY(EapQtPluginHandlePrivate)

private: // data

    EapQtExpandedEapType mType;
    int mProtocolImplementationUid;

    // Friend classes
    friend class EapQtPluginHandle;

};

#endif // EAPQTPLUGINHANDLE_P_H
