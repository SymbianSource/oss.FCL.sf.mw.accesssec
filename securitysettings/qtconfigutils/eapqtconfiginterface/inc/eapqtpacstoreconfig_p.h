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
 *   EAP-FAST PAC store configuration data (private part)
 *
 */

/*
 * %version: 2 %
 */

#ifndef EAPQTPACSTORECONFIG_P_H
#define EAPQTPACSTORECONFIG_P_H

// System includes
#include <QHash>
#include <QVariant>

// User includes

// Forward declarations

// External data types

// Constants

// Class declaration
class  EapQtPacStoreConfigPrivate
{

public:

    // Data types

    EapQtPacStoreConfigPrivate();
    ~EapQtPacStoreConfigPrivate();

private:

    Q_DISABLE_COPY(EapQtPacStoreConfigPrivate)

private: // data

    QHash<int, QVariant> mPacStoreSettings;

    // Friend classes
    friend class EapQtPacStoreConfig;

};

#endif // EAPQTPACSTORECONFIG_P_H
