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
 * %version: 5 %
 */

#ifndef EAPQTEXPANDEDEAPTYPE_H
#define EAPQTEXPANDEDEAPTYPE_H

// System includes
#include <QByteArray>
#include <QMetaType>
#include <eapqtconfigexport.h>

// User includes

// Forward declarations
class EapQtExpandedEapTypePrivate;

// External data types

// Constants

// Class declaration
class EAP_QT_PLUGIN_INFO_EXPORT EapQtExpandedEapType
{

public:

    // Data types

    enum Type
    {
        TypeUndefined = 0,
        TypeEapAka,
        TypeEapFast,
        TypeEapGtc,
        TypeLeap,
        TypeEapMschapv2,
        TypePeap,
        TypeEapSim,
        TypeEapTls,
        TypeEapTtls,
        TypeProtectedSetup,
        TypePap,
        TypePlainMschapv2,
        // marker for the last item
        TypeLast
    };

    // default constructor
    EapQtExpandedEapType();

    // constructs an instance from an EapQtExpandedEapType::Type value
    EapQtExpandedEapType(const Type type);

    // constructs an instance from expanded EAP type binary data,
    // see RFC3748
    EapQtExpandedEapType(const QByteArray &data);

    // copy constructor
    EapQtExpandedEapType(const EapQtExpandedEapType &type);

    // destructor
    ~EapQtExpandedEapType();

    // returns expanded EAP type binary data,
    // see RFC3748
    QByteArray eapExpandedData() const;

    // returns EapQtExpandedEapType::Type of the instance
    Type type() const;

    // assignment
    EapQtExpandedEapType &operator=(const EapQtExpandedEapType &type);

    // comparisons
    bool operator ==(const EapQtExpandedEapType &right_type_value) const;
    bool operator !=(const EapQtExpandedEapType &right_type_value) const;

private: // data

    QScopedPointer<EapQtExpandedEapTypePrivate> d_ptr;

};

// Make the class known to QMetaType to support using QVariant
Q_DECLARE_METATYPE(EapQtExpandedEapType)

#endif // EAPQTEXTENDEDEAPTYPE_H
