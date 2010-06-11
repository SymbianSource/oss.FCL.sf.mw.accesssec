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
 *   EAP method QT configuration
 *
 */

/*
 * %version: 4 %
 */

#ifndef EAPQTCONFIG_P_H
#define EAPQTCONFIG_P_H

#include <QHash>
#include <QVariant>

class EapQtConfigPrivate
{
    friend class EapQtConfig;

public:
    EapQtConfigPrivate();
    ~EapQtConfigPrivate();

private:
    Q_DISABLE_COPY(EapQtConfigPrivate)
    QHash<int, QVariant> mSettings;
};

#endif /* EAPQTCONFIG_P_H */
