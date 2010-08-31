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
 * %version: 4 %
 */

#ifndef EAPQTPLUGININFO_P_H
#define EAPQTPLUGININFO_P_H

// System includes
#include <QString>
#include <eapqtpluginhandle.h>

// User includes

// Forward declarations

// External data types

// Constants

// Class declaration
class EapQtPluginInfoPrivate
{

public:

    // Data types

    EapQtPluginInfoPrivate(const EapQtPluginHandle &mHandle, const QString &locId,
        const int orderNumber);
    ~EapQtPluginInfoPrivate();

private:

    EapQtPluginInfoPrivate();
    Q_DISABLE_COPY(EapQtPluginInfoPrivate)

private: // data

    EapQtPluginHandle mHandle;
    QString mLocId;
    int mOrderNumber;

    // Friend classes
    friend class EapQtPluginInfo;

};

#endif // EAPPLUGININFO_P_H
