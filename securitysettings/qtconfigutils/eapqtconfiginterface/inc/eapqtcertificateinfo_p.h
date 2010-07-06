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
 *   Certificate information data structure for EAP QT configuration interface
 *
 */

/*
 * %version: 4 %
 */

#ifndef EAPQTCERTIFICATEINFO_P_H
#define EAPQTCERTIFICATEINFO_P_H

// System includes
#include <QHash>
#include <QVariant>

// User includes

// Forward declarations

// External data types

// Constants

// Class declaration
class EapQtCertificateInfoPrivate
{

public:

    // Data types

    EapQtCertificateInfoPrivate();
    ~EapQtCertificateInfoPrivate();
    
    // copy constructor
    EapQtCertificateInfoPrivate(const EapQtCertificateInfoPrivate &certInfo);

    QVariant value(const int id);
    void setValue(const int id, const QVariant &newValue);
    void clear();

private:

    // disable assignment
    EapQtCertificateInfoPrivate &operator=(const EapQtCertificateInfoPrivate&);

private: // data

    QHash<int, QVariant> mCerts;

};

#endif // EAPQTCERTIFICATEINFO_P_H
