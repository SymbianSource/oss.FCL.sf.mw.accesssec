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
 *   EAP UI plugin information
 *
 */

/*
 * %version: 5 %
 */

#ifndef EAPQTPLUGININFO_H
#define EAPQTPLUGININFO_H

// System includes
#include <QString>
#include <eapqtconfigexport.h>

// User includes

// Forward declarations
class EapQtPluginHandle;
class EapQtPluginInfoPrivate;

// External data types

// Constants

// Class declaration
class EAP_QT_PLUGIN_INFO_EXPORT EapQtPluginInfo
{

public:

    // Data types

    // copy constructor
    EapQtPluginInfo(const EapQtPluginInfo &info);

    // constructs an instance from an plugin handle,
    // plugin name as a string (e.g. "EAP-SIM") used on the UI, and oder number;
    // order number specifies the location of the plugin in lists of
    // EAP plugins shown on the UI
    EapQtPluginInfo(const EapQtPluginHandle &id, const QString &locId, const int orderNumber );

    // destructor
    ~EapQtPluginInfo();

    // returns plugin handle of the instance
    EapQtPluginHandle pluginHandle() const;

    // returns plugin name string of the instance
    QString localizationId() const;

    // returns order number of the instance
    int orderNumber() const;

    // assignment
    EapQtPluginInfo &operator=(const EapQtPluginInfo &info);
    
private:
    EapQtPluginInfo();

private: // data

    QScopedPointer<EapQtPluginInfoPrivate> d_ptr;

};

#endif // EAPQTPLUGININFO_H
