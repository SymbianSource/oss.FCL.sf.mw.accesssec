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
 *   Control Panel EAP plugin information
 *
 */

/*
 * %version: 2 %
 */


#ifndef EAPQTPLUGINHANDLE_P_H
#define EAPQTPLUGINHANDLE_P_H

#include "eapqtexpandedeaptype.h"

class EapQtPluginHandlePrivate
{
    friend class EapQtPluginHandle;

public:
    EapQtPluginHandlePrivate(EapQtExpandedEapType type, int uid);
    ~EapQtPluginHandlePrivate();

private:
    EapQtPluginHandlePrivate();
    Q_DISABLE_COPY(EapQtPluginHandlePrivate)
    EapQtExpandedEapType mType;
    int mProtocolImplementationUid;
};

#endif /* EAPQTPLUGINHANDLE_P_H */
