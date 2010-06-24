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
 *   EAP method QT configuration
 *
 */

/*
 * %version: 5 %
 */

#ifndef EAPQTCONFIG_P_H
#define EAPQTCONFIG_P_H

// System includes
#include <QHash>
#include <QVariant>

// User includes

// Forward declarations

// External data types

// Constants

// Class declaration
class EapQtConfigPrivate
{

public:

    // Data types

    EapQtConfigPrivate();
    ~EapQtConfigPrivate();

private:

    Q_DISABLE_COPY(EapQtConfigPrivate)

private: // data

    QHash<int, QVariant> mSettings;

    // Friend classes
    friend class EapQtConfig;
};

#endif // EAPQTCONFIG_P_H
