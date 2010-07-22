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
 *   Expanded EAP type QT data structure
 *
 */

/*
 * %version: 4 %
 */

#ifndef EAPQTEXPANDEDEAPTYPE_P_H
#define EAPQTEXPANDEDEAPTYPE_P_H

// System includes
#include <QByteArray>
#include <eapqtexpandedeaptype.h>

// User includes

// Forward declarations

// External data types

// Constants

// Class declaration
class EapQtExpandedEapTypePrivate
{

public:

    // Data types

    EapQtExpandedEapTypePrivate();
    EapQtExpandedEapTypePrivate(const EapQtExpandedEapType::Type type);
    EapQtExpandedEapTypePrivate(const QByteArray &data);
    
    ~EapQtExpandedEapTypePrivate();

private:

    Q_DISABLE_COPY(EapQtExpandedEapTypePrivate)

private: // data

    QByteArray mData;
    EapQtExpandedEapType::Type mType;

    // Friend classes
    friend class EapQtExpandedEapType;

};

#endif // EAPQTEXPANDEDEAPTYPE_P_H
