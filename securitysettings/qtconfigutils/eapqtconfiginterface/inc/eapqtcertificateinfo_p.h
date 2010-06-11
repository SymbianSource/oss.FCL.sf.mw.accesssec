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
 *   Certificate information data structure for EAP QT configuration interface
 *
 */

/*
 * %version: 3 %
 */

#ifndef EAPQTCERTIFICATEINFO_P_H
#define EAPQTCERTIFICATEINFO_P_H

#include <QHash>
#include <QVariant>

class EapQtCertificateInfoPrivate
{
public:

    EapQtCertificateInfoPrivate();
    ~EapQtCertificateInfoPrivate();
    
    // copy constructor
    EapQtCertificateInfoPrivate(const EapQtCertificateInfoPrivate &certInfo);

    QVariant value(int id);
    void setValue(int id, QVariant newValue);

private:
    // disable assignment
    EapQtCertificateInfoPrivate &operator=(const EapQtCertificateInfoPrivate&);
    QHash<int, QVariant> mCerts;

};

#endif /* EAPQTCERTIFICATEINFO_P_H */
