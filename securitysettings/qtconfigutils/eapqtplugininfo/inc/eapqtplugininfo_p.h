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
 * %version: 3 %
 */

#ifndef EAPQTPLUGININFO_P_H
#define EAPQTPLUGININFO_P_H

#include <QString>
#include "eapqtpluginhandle.h"

class EapQtPluginInfoPrivate
{
    friend class EapQtPluginInfo;

public:
    EapQtPluginInfoPrivate(EapQtPluginHandle mHandle, QString locId, int orderNumber);
    ~EapQtPluginInfoPrivate();

private:
    EapQtPluginInfoPrivate();
    Q_DISABLE_COPY(EapQtPluginInfoPrivate)
    EapQtPluginHandle mHandle;
    QString mLocId;
    int mOrderNumber;
};

#endif /* EAPPLUGININFO_P_H */
